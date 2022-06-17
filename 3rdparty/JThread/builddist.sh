#!/bin/bash

VERSION=`cat CMakeLists.txt|grep VERSION | grep set | head -n 1 |cut -f 2 -d " "|cut -f 1 -d ")"`
LIBNAME=jthread
TMPDIR=`tempfile`
CURDIR=`pwd`
rm -r $TMPDIR
if ! mkdir $TMPDIR ; then
	echo "Couldn't create temporary directory"
	exit -1
fi

cd $TMPDIR
TMPDIR=`pwd` # Get the full path
cd $CURDIR

if ! git archive --format tar --prefix=${LIBNAME}-${VERSION}/ HEAD | (cd $TMPDIR && tar xf -) ; then
	echo "Couldn't archive repository"
	exit -1
fi

cd $TMPDIR/${LIBNAME}-${VERSION}

rm -f `find . -name ".git*"`
rm -f builddist.sh
rm -rf sphinxdoc
rm -f TODO
	
cd ..

if ! tar cfz ${LIBNAME}-${VERSION}.tar.gz ${LIBNAME}-${VERSION}/ ; then
	echo "Couldn't create archive"
	exit -1
fi

if ! tar cfj ${LIBNAME}-${VERSION}.tar.bz2 ${LIBNAME}-${VERSION}/ ; then
	echo "Couldn't create archive"
	exit -1
fi

if ! zip ${LIBNAME}-${VERSION}.zip `find ${LIBNAME}-${VERSION}/` ; then
	echo "Couldn't create archive"
	exit -1
fi

mv $TMPDIR $CURDIR/


