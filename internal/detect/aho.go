package detect

// ac is an Aho-Corasick automaton over bytes, laid out to stay small with
// tens of thousands of needles. The original design is in
// internal/wappalyzer/literal_index.go; this one stores edges sparsely
// (a dense table per node would cost 1 KiB each) and keeps full transition
// tables only for the shallow nodes every scan passes through.
type ac struct {
	dense   []int32 // dense*256 transitions for nodes 0..nDense-1 (BFS order)
	nDense  int32
	edgeOff []int32 // node -> first edge, len nodes+1
	edgeCh  []byte
	edgeTo  []int32
	fail    []int32
	outOff  []int32 // node -> first own output
	outIDs  []int32
	link    []int32 // nearest proper suffix node with outputs, or -1
}

const denseDepth = 2

type acBuilder struct {
	first []int32 // first child
	next  []int32 // next sibling
	ch    []byte
	depth []uint8
	outs  map[int32][]int32
}

func newACBuilder() *acBuilder {
	return &acBuilder{first: []int32{-1}, next: []int32{-1}, ch: []byte{0}, depth: []uint8{0}, outs: map[int32][]int32{}}
}

func (b *acBuilder) child(n int32, c byte) int32 {
	for k := b.first[n]; k >= 0; k = b.next[k] {
		if b.ch[k] == c {
			return k
		}
	}
	return -1
}

func (b *acBuilder) add(needle string, id int32) {
	n := int32(0)
	for i := 0; i < len(needle); i++ {
		k := b.child(n, needle[i])
		if k < 0 {
			k = int32(len(b.first))
			b.first = append(b.first, -1)
			b.next = append(b.next, b.first[n])
			b.ch = append(b.ch, needle[i])
			d := b.depth[n]
			if d < 255 {
				d++
			}
			b.depth = append(b.depth, d)
			b.first[n] = k
		}
		n = k
	}
	b.outs[n] = append(b.outs[n], id)
}

// build renumbers nodes in BFS order so the shallow ones are a prefix.
func (b *acBuilder) build() *ac {
	total := len(b.first)
	order := make([]int32, 0, total) // new id -> old id
	order = append(order, 0)
	parent := make([]int32, total)
	for head := 0; head < len(order); head++ {
		old := order[head]
		kids := b.sortedChildren(old)
		for _, k := range kids {
			parent[k] = old
			order = append(order, k)
		}
	}
	newID := make([]int32, total)
	for ni, old := range order {
		newID[old] = int32(ni)
	}

	a := &ac{
		edgeOff: make([]int32, total+1),
		fail:    make([]int32, total),
		outOff:  make([]int32, total+1),
		link:    make([]int32, total),
	}
	for ni, old := range order {
		a.edgeOff[ni] = int32(len(a.edgeCh))
		for _, k := range b.sortedChildren(old) {
			a.edgeCh = append(a.edgeCh, b.ch[k])
			a.edgeTo = append(a.edgeTo, newID[k])
		}
		a.outOff[ni] = int32(len(a.outIDs))
		a.outIDs = append(a.outIDs, b.outs[old]...)
	}
	a.edgeOff[total] = int32(len(a.edgeCh))
	a.outOff[total] = int32(len(a.outIDs))

	for ni := 1; ni < total; ni++ {
		if b.depth[order[ni]] <= denseDepth {
			a.nDense = int32(ni) + 1
		}
	}
	a.nDense = max(a.nDense, 1)
	a.dense = make([]int32, int(a.nDense)*256)

	a.link[0] = -1
	// Failure links in BFS order: a node's parent is processed first.
	for ni := 1; ni < total; ni++ {
		p := newID[parent[order[ni]]]
		c := b.ch[order[ni]]
		if p == 0 {
			a.fail[ni] = 0
		} else {
			f := a.fail[p]
			for {
				if to := a.edge(f, c); to > 0 {
					a.fail[ni] = to
					break
				}
				if f == 0 {
					a.fail[ni] = 0
					break
				}
				f = a.fail[f]
			}
		}
		f := a.fail[ni]
		if a.outOff[f+1] > a.outOff[f] {
			a.link[ni] = f
		} else {
			a.link[ni] = a.link[f]
		}
	}
	for ni := int32(0); ni < a.nDense; ni++ {
		for c := 0; c < 256; c++ {
			if to := a.edge(ni, byte(c)); to > 0 {
				a.dense[int(ni)*256+c] = to
			} else if ni > 0 {
				a.dense[int(ni)*256+c] = a.dense[int(a.fail[ni])*256+c]
			}
		}
	}
	return a
}

func (b *acBuilder) sortedChildren(n int32) []int32 {
	var kids []int32
	for k := b.first[n]; k >= 0; k = b.next[k] {
		kids = append(kids, k)
	}
	for i := 1; i < len(kids); i++ {
		for j := i; j > 0 && b.ch[kids[j]] < b.ch[kids[j-1]]; j-- {
			kids[j], kids[j-1] = kids[j-1], kids[j]
		}
	}
	return kids
}

// edge is the trie child of node n on c, or 0 (the root is never a child).
func (a *ac) edge(n int32, c byte) int32 {
	lo, hi := int(a.edgeOff[n]), int(a.edgeOff[n+1])
	if hi-lo <= 8 {
		for i := lo; i < hi; i++ {
			if a.edgeCh[i] == c {
				return a.edgeTo[i]
			}
		}
		return 0
	}
	for lo < hi {
		mid := int(uint(lo+hi) >> 1)
		if a.edgeCh[mid] < c {
			lo = mid + 1
		} else {
			hi = mid
		}
	}
	if lo < int(a.edgeOff[n+1]) && a.edgeCh[lo] == c {
		return a.edgeTo[lo]
	}
	return 0
}

// scan calls found for every needle id that occurs in text.
func (a *ac) scan(text string, found func(id int32)) {
	var s int32
	for i := 0; i < len(text); i++ {
		c := text[i]
		if s < a.nDense {
			s = a.dense[int(s)*256+int(c)]
		} else {
			for {
				if to := a.edge(s, c); to > 0 {
					s = to
					break
				}
				s = a.fail[s]
				if s < a.nDense {
					s = a.dense[int(s)*256+int(c)]
					break
				}
			}
		}
		for o := s; o >= 0; o = a.link[o] {
			for _, id := range a.outIDs[a.outOff[o]:a.outOff[o+1]] {
				found(id)
			}
		}
	}
}
