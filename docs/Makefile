# re-run when whack.cddl changes
../include/whack_values.h: whack.cddl
	(cat whack_values_head.h; cddlc --to=enum whack.cddl; cat whack_values_tail.h) >../include/whack_values.h
