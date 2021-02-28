fn test_inline_asm() {
	a, b := 10, 0
	asm amd64 {
		mov eax, a
		mov b, eax
		: (b)
		: (a)
	}
	assert a == 10
	assert b == 10

	c := 0
	asm amd64 {
		mov c, 5
		: (c)

	}
	assert c == 5

	d, e, f := 10, 2, 0
	asm amd64 {
		mov f, d
		add f, e
		add f, 5
		:  (f) // output 
		:  (d)
		   (e) // input 
	}
	assert d == 10
	assert e == 2
	assert f == 17

	// g, h, i := 2.3, 4.8, -3.5
	// asm rv64 {
	// 	fadd.s $i, $g, $h // test `.` in instruction name
	// 	: =r (i) as i
	// 	: r (g) as g
	// 	  r (g) as h
	// }
	// assert g == 2.3
	// assert h == 4.8
	// assert i == 7.1

	mut j := 0
	// do 5*3
	// adding three, five times
	asm amd64 {
		mov rcx, 5 // loop 5 times
		loop_start:
		add j, 3
		loop loop_start
		: (j)

	}
	assert j == 5 * 3

	// k := 0 // Wait for tcc to implement goto, and gcc has odd errors
	// mut loops := 0
	// outside_label:
	// if k != 5 {
	// 	loops++
	// 	asm goto amd64 {
	// 		mov k, 1
	// 		mov k, 5
	// 		jmp outside_label
	// 		: =r (k) as k
	// 		: r (k)
	// 		:
	// 		: outside_label
	// 	}
	// }
	// assert loops == 1
	// assert k == 5

	l := 5
	m := &l
	asm amd64 {
		movq [m], 7 // have to specify size with q
		: : (m)
	}
	assert l == 7

	n := [5, 9, 0, 4]
	asm amd64 {
		loop_start2:
		addq [in_data + rcx * 4 + 0], 2
		loop loop_start2
		addq [in_data + rcx * 4 + 0], 2
		: : c (n.len - 1) // c is counter (loop) register
		  (n.data) as in_data
	}
	assert n == [7, 11, 2, 6]

	// m := `d`
	// asm amd64 {
	// 	cmp m, 0
	// 	je inif
	// 	mov m, `p`
	// 	jmp end
	// 	inif:
	// 	mov m, `l`
	// 	end:
	// 	: =r (m) as m
	// }	
	// assert m == `l`
}
