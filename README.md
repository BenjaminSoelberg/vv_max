This project aims to solve Flareon6 challenge 11 using the Z3 solver.

The overall architecture is to emulate all the used AVX2 instructions good enough to solve the challenge.

It works much like a CPU where AVX2 instructions are implemented as z3 constraints. 
I don't know much about Z3 or actually how to use it effectively but this gets the job done.

The "self.builder.bitvec_name_prefix" helps to assert that the Z3 solver follows the actual values in the original
program by giving each resulting bitvec a "meaningful" name that corresponds to the IP and instruction in the VM.

I had a lot of problems with signed/unsigned vales as well as endianness. Z3 uses big endian and intel little endian.
But in the end it didn't seems to matter. Only the signed stuff probably has bugs but works good enough for now.

The vpermd instruction has 1. and 2. operand reversed with respect to the intel manual which also caused some headache.

All in all a very good (yet frustrating) learning experience with Z3.

A few key takeaways when using Z3:
* Write unit tests
* Give each BitVec a meaningful name.
* Add as many constraints as you can think of.