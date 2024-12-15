HAVE_LIBUNWIND=0
LIBUNWIND_LIBS=
AC_CHECK_HEADER([libunwind.h],[
    XLIBS=$LIBS
    LIBS=""
    AC_CHECK_LIB([unwind],[perror],[
        HAVE_LIBUNWIND=1
        AC_DEFINE([HAVE_LIBUNWIND], 1, [libunwind])
        LIBUNWIND_LIBS="-lunwind"
    ])
    LIBS=$XLIBS
])
AC_SUBST([LIBUNWIND_LIBS])
