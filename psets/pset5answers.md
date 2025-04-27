CS 161 Problem Set 5 Answers
============================
Leave your name out of this file. Put collaboration notes and credit in
`pset5collab.md`.

Answers to written questions
----------------------------


File_descriptor_lock -> knew it during fork and have a pointer field to it in our proc so we can share it across different threads -> can just dereference and lock it (DON'T FORGET TO KFREE IT IN SYS_TEXIT)

Grading notes
-------------
