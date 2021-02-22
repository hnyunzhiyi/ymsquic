# Building YmsQuic
Linux:
    Building with CMake:
      Download latest epel-release rpm from
	http://download-ib01.fedoraproject.org/pub/epel/7/x86_64
      Install epel-release rpm:
        rpm -Uvh epel-release*rpm
      Install cmake3 rpm package:
        yum install cmake3
      Install atomic package
        yum -y install  libatomic
      Install ymsquic 
	./Ymsquic/scripts/build.sh -Tls stub

