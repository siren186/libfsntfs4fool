/*
 * Library compression_unit_descriptor type test program
 *
 * Copyright (C) 2010-2022, Joachim Metz <joachim.metz@gmail.com>
 *
 * Refer to AUTHORS for acknowledgements.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#include <common.h>
#include <file_stream.h>
#include <types.h>

#if defined( HAVE_STDLIB_H ) || defined( WINAPI )
#include <stdlib.h>
#endif

#include "fsntfs_test_libcerror.h"
#include "fsntfs_test_libfsntfs.h"
#include "fsntfs_test_macros.h"
#include "fsntfs_test_memory.h"
#include "fsntfs_test_unused.h"

#include "../libfsntfs/libfsntfs_compression_unit_descriptor.h"

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

/* Tests the libfsntfs_compression_unit_descriptor_initialize function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_compression_unit_descriptor_initialize(
     void )
{
	libcerror_error_t *error                                             = NULL;
	libfsntfs_compression_unit_descriptor_t *compression_unit_descriptor = NULL;
	int result                                                           = 0;

#if defined( HAVE_FSNTFS_TEST_MEMORY )
	int number_of_malloc_fail_tests                                      = 1;
	int number_of_memset_fail_tests                                      = 1;
	int test_number                                                      = 0;
#endif

	/* Test regular cases
	 */
	result = libfsntfs_compression_unit_descriptor_initialize(
	          &compression_unit_descriptor,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "compression_unit_descriptor",
	 compression_unit_descriptor );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_compression_unit_descriptor_free(
	          &compression_unit_descriptor,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "compression_unit_descriptor",
	 compression_unit_descriptor );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfsntfs_compression_unit_descriptor_initialize(
	          NULL,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	compression_unit_descriptor = (libfsntfs_compression_unit_descriptor_t *) 0x12345678UL;

	result = libfsntfs_compression_unit_descriptor_initialize(
	          &compression_unit_descriptor,
	          &error );

	compression_unit_descriptor = NULL;

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

#if defined( HAVE_FSNTFS_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libfsntfs_compression_unit_descriptor_initialize with malloc failing
		 */
		fsntfs_test_malloc_attempts_before_fail = test_number;

		result = libfsntfs_compression_unit_descriptor_initialize(
		          &compression_unit_descriptor,
		          &error );

		if( fsntfs_test_malloc_attempts_before_fail != -1 )
		{
			fsntfs_test_malloc_attempts_before_fail = -1;

			if( compression_unit_descriptor != NULL )
			{
				libfsntfs_compression_unit_descriptor_free(
				 &compression_unit_descriptor,
				 NULL );
			}
		}
		else
		{
			FSNTFS_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			FSNTFS_TEST_ASSERT_IS_NULL(
			 "compression_unit_descriptor",
			 compression_unit_descriptor );

			FSNTFS_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
	for( test_number = 0;
	     test_number < number_of_memset_fail_tests;
	     test_number++ )
	{
		/* Test libfsntfs_compression_unit_descriptor_initialize with memset failing
		 */
		fsntfs_test_memset_attempts_before_fail = test_number;

		result = libfsntfs_compression_unit_descriptor_initialize(
		          &compression_unit_descriptor,
		          &error );

		if( fsntfs_test_memset_attempts_before_fail != -1 )
		{
			fsntfs_test_memset_attempts_before_fail = -1;

			if( compression_unit_descriptor != NULL )
			{
				libfsntfs_compression_unit_descriptor_free(
				 &compression_unit_descriptor,
				 NULL );
			}
		}
		else
		{
			FSNTFS_TEST_ASSERT_EQUAL_INT(
			 "result",
			 result,
			 -1 );

			FSNTFS_TEST_ASSERT_IS_NULL(
			 "compression_unit_descriptor",
			 compression_unit_descriptor );

			FSNTFS_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( HAVE_FSNTFS_TEST_MEMORY ) */

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( compression_unit_descriptor != NULL )
	{
		libfsntfs_compression_unit_descriptor_free(
		 &compression_unit_descriptor,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_compression_unit_descriptor_free function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_compression_unit_descriptor_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libfsntfs_compression_unit_descriptor_free(
	          NULL,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	return( 0 );
}

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

/* The main program
 */
#if defined( HAVE_WIDE_SYSTEM_CHARACTER )
int wmain(
     int argc FSNTFS_TEST_ATTRIBUTE_UNUSED,
     wchar_t * const argv[] FSNTFS_TEST_ATTRIBUTE_UNUSED )
#else
int main(
     int argc FSNTFS_TEST_ATTRIBUTE_UNUSED,
     char * const argv[] FSNTFS_TEST_ATTRIBUTE_UNUSED )
#endif
{
	FSNTFS_TEST_UNREFERENCED_PARAMETER( argc )
	FSNTFS_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

	FSNTFS_TEST_RUN(
	 "libfsntfs_compression_unit_descriptor_initialize",
	 fsntfs_test_compression_unit_descriptor_initialize );

	FSNTFS_TEST_RUN(
	 "libfsntfs_compression_unit_descriptor_free",
	 fsntfs_test_compression_unit_descriptor_free );

	/* TODO: add tests for libfsntfs_compression_unit_descriptor_append_data_segment */

	/* TODO: add tests for libfsntfs_compression_unit_descriptor_print */

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

