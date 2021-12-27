# working-on
running the main now:
- create new ec2.
- install all the things there.
- the creator class attaches the wanted volume to the ec2 we created. then mount it to local folder from the command script.
- running most of the checks and save them as jsons on the created ec2.

todo:
- support vuls running on the new volume. the problem is with ssh to the new root. this is the last major fix (well, probably).

before running:
-  /newvolumes has different numbers throughout the code.
-  change "idan15" key name :)
-  test more (especially around the sudo topic) the subprocess pip installation.
-  change device name in class (not crucial).
