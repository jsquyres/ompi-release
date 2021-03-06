#
# Copyright (c) 2004-2009 The Trustees of Indiana University and Indiana
#                         University Research and Technology
#                         Corporation.  All rights reserved.
# Copyright (c) 2004-2005 The University of Tennessee and The University
#                         of Tennessee Research Foundation.  All rights
#                         reserved.
# Copyright (c) 2004-2005 High Performance Computing Center Stuttgart, 
#                         University of Stuttgart.  All rights reserved.
# Copyright (c) 2004-2005 The Regents of the University of California.
#                         All rights reserved.
# Copyright (c) 2006-2012 Cisco Systems, Inc.  All rights reserved.
# Copyright (c) 2009-2011 Oak Ridge National Labs.  All rights reserved.
# Copyright (c) 2014      Research Organization for Information Science
#                         and Technology (RIST). All rights reserved.
# $COPYRIGHT$
# 
# Additional copyrights may follow
# 
# $HEADER$
#

# Note - headers and nodist_headers will go in ${includedir}/openmpi,
# not ${includedir}/
headers = ompi_config.h
nodist_headers =

# Install these in $(includedir)
include_HEADERS = 

# Always install these in $(pkgincludedir)
pkginclude_HEADERS =

if OMPI_BUILD_FORTRAN_MPIFH_BINDINGS
include_HEADERS += \
        mpif-constants.h \
        mpif-externals.h \
        mpif-handles.h \
        mpif-io-constants.h \
        mpif-io-handles.h \
        mpif-sentinels.h

endif

# These files are always installed in $(includedir), but shouldn't be
# shipped since they are generated by configure from their .in
# counterparts (which AM automatically ships).
nodist_include_HEADERS = \
        mpi.h \
        mpi-ext.h \
        mpif.h \
        mpif-ext.h \
	mpi_portable_platform.h

if OMPI_BUILD_FORTRAN_MPIFH_BINDINGS
nodist_include_HEADERS += \
        mpif-config.h
endif

include ompi/Makefile.am

# This is complicated, but mpif-values.pl generates
# several mpif-*.h files in this directory (during autogen.pl).
# Hence, if any of those files change, it's safer to just force the
# user to re-autogen.
#mpif.h: mpif-constants.h mpif-handles.h mpif-io-constants.h mpif-io-handles.h
#	@ echo "ERROR: an mpi-*.h header file has changed"
#	@ echo "ERROR: you must re-run autogen.pl (sorry!)"
#	@ exit 1

EXTRA_DIST = $(headers) mpif-values.pl

if WANT_INSTALL_HEADERS 
ompidir = $(ompiincludedir)
nobase_dist_ompi_HEADERS = $(headers)
nobase_nodist_ompi_HEADERS = $(nodist_headers)
endif

# Remove the auto-generated files (they are generated by configure)
# Since there is no mpi-ext.h.in, autogen does not know to cleanup this file.
distclean-local:
	rm -f mpi-ext.h mpif-ext.h mpi_portable_platform.h

mpi_portable_platform.h: $(top_srcdir)/opal/include/opal/opal_portable_platform.h
	$(LN_S) $(top_srcdir)/opal/include/opal/opal_portable_platform.h mpi_portable_platform.h
