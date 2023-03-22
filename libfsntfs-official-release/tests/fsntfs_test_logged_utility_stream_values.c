/*
 * Library logged_utility_stream_values type test program
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

#include "../libfsntfs/libfsntfs_io_handle.h"
#include "../libfsntfs/libfsntfs_mft_attribute.h"
#include "../libfsntfs/libfsntfs_logged_utility_stream_values.h"

/* TODO replace by non TxF data logged utility stream
 */
uint8_t fsntfs_test_logged_utility_stream_values_data1[ 104 ] = {
	0x00, 0x01, 0x00, 0x00, 0x68, 0x00, 0x00, 0x00, 0x00, 0x09, 0x18, 0x00, 0x00, 0x00, 0x09, 0x00,
	0x38, 0x00, 0x00, 0x00, 0x30, 0x00, 0x00, 0x00, 0x24, 0x00, 0x54, 0x00, 0x58, 0x00, 0x46, 0x00,
	0x5f, 0x00, 0x44, 0x00, 0x41, 0x00, 0x54, 0x00, 0x41, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00 };

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

/* Tests the libfsntfs_logged_utility_stream_values_initialize function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_logged_utility_stream_values_initialize(
     void )
{
	libcerror_error_t *error                                               = NULL;
	libfsntfs_logged_utility_stream_values_t *logged_utility_stream_values = NULL;
	int result                                                             = 0;

#if defined( HAVE_FSNTFS_TEST_MEMORY )
	int number_of_malloc_fail_tests                                        = 1;
	int number_of_memset_fail_tests                                        = 1;
	int test_number                                                        = 0;
#endif

	/* Test regular cases
	 */
	result = libfsntfs_logged_utility_stream_values_initialize(
	          &logged_utility_stream_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "logged_utility_stream_values",
	 logged_utility_stream_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_logged_utility_stream_values_free(
	          &logged_utility_stream_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "logged_utility_stream_values",
	 logged_utility_stream_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfsntfs_logged_utility_stream_values_initialize(
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

	logged_utility_stream_values = (libfsntfs_logged_utility_stream_values_t *) 0x12345678UL;

	result = libfsntfs_logged_utility_stream_values_initialize(
	          &logged_utility_stream_values,
	          &error );

	logged_utility_stream_values = NULL;

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
		/* Test libfsntfs_logged_utility_stream_values_initialize with malloc failing
		 */
		fsntfs_test_malloc_attempts_before_fail = test_number;

		result = libfsntfs_logged_utility_stream_values_initialize(
		          &logged_utility_stream_values,
		          &error );

		if( fsntfs_test_malloc_attempts_before_fail != -1 )
		{
			fsntfs_test_malloc_attempts_before_fail = -1;

			if( logged_utility_stream_values != NULL )
			{
				libfsntfs_logged_utility_stream_values_free(
				 &logged_utility_stream_values,
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
			 "logged_utility_stream_values",
			 logged_utility_stream_values );

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
		/* Test libfsntfs_logged_utility_stream_values_initialize with memset failing
		 */
		fsntfs_test_memset_attempts_before_fail = test_number;

		result = libfsntfs_logged_utility_stream_values_initialize(
		          &logged_utility_stream_values,
		          &error );

		if( fsntfs_test_memset_attempts_before_fail != -1 )
		{
			fsntfs_test_memset_attempts_before_fail = -1;

			if( logged_utility_stream_values != NULL )
			{
				libfsntfs_logged_utility_stream_values_free(
				 &logged_utility_stream_values,
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
			 "logged_utility_stream_values",
			 logged_utility_stream_values );

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
	if( logged_utility_stream_values != NULL )
	{
		libfsntfs_logged_utility_stream_values_free(
		 &logged_utility_stream_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_logged_utility_stream_values_free function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_logged_utility_stream_values_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libfsntfs_logged_utility_stream_values_free(
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

/* Tests the libfsntfs_logged_utility_stream_values_read_data function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_logged_utility_stream_values_read_data(
     void )
{
	libcerror_error_t *error                                               = NULL;
	libfsntfs_logged_utility_stream_values_t *logged_utility_stream_values = NULL;
	int result                                                             = 0;

	/* Initialize test
	 */
	result = libfsntfs_logged_utility_stream_values_initialize(
	          &logged_utility_stream_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "logged_utility_stream_values",
	 logged_utility_stream_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_logged_utility_stream_values_read_data(
	          logged_utility_stream_values,
	          &( fsntfs_test_logged_utility_stream_values_data1[ 42 ] ),
	          56,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfsntfs_logged_utility_stream_values_read_data(
	          NULL,
	          &( fsntfs_test_logged_utility_stream_values_data1[ 42 ] ),
	          56,
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

	result = libfsntfs_logged_utility_stream_values_read_data(
	          logged_utility_stream_values,
	          NULL,
	          56,
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

	result = libfsntfs_logged_utility_stream_values_read_data(
	          logged_utility_stream_values,
	          &( fsntfs_test_logged_utility_stream_values_data1[ 42 ] ),
	          (size_t) SSIZE_MAX + 1,
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

	result = libfsntfs_logged_utility_stream_values_read_data(
	          logged_utility_stream_values,
	          &( fsntfs_test_logged_utility_stream_values_data1[ 42 ] ),
	          0,
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

	/* Clean up
	 */
	result = libfsntfs_logged_utility_stream_values_free(
	          &logged_utility_stream_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "logged_utility_stream_values",
	 logged_utility_stream_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( logged_utility_stream_values != NULL )
	{
		libfsntfs_logged_utility_stream_values_free(
		 &logged_utility_stream_values,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_logged_utility_stream_values_read_from_mft_attribute function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_logged_utility_stream_values_read_from_mft_attribute(
     void )
{
	libcerror_error_t *error                                               = NULL;
	libfsntfs_io_handle_t *io_handle                                       = NULL;
	libfsntfs_logged_utility_stream_values_t *logged_utility_stream_values = NULL;
	libfsntfs_mft_attribute_t *mft_attribute                               = NULL;
	int result                                                             = 0;

	/* Initialize test
	 */
	result = libfsntfs_io_handle_initialize(
	          &io_handle,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "io_handle",
	 io_handle );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	io_handle->cluster_block_size = 4096;

	result = libfsntfs_mft_attribute_initialize(
	          &mft_attribute,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "mft_attribute",
	 mft_attribute );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_mft_attribute_read_data(
	          mft_attribute,
	          io_handle,
	          fsntfs_test_logged_utility_stream_values_data1,
	          104,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_logged_utility_stream_values_initialize(
	          &logged_utility_stream_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "logged_utility_stream_values",
	 logged_utility_stream_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_logged_utility_stream_values_read_from_mft_attribute(
	          logged_utility_stream_values,
	          mft_attribute,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfsntfs_logged_utility_stream_values_read_from_mft_attribute(
	          NULL,
	          mft_attribute,
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

	result = libfsntfs_logged_utility_stream_values_read_from_mft_attribute(
	          logged_utility_stream_values,
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

	/* Clean up
	 */
	result = libfsntfs_logged_utility_stream_values_free(
	          &logged_utility_stream_values,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "logged_utility_stream_values",
	 logged_utility_stream_values );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_mft_attribute_free(
	          &mft_attribute,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "mft_attribute",
	 mft_attribute );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_io_handle_free(
	          &io_handle,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "io_handle",
	 io_handle );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( logged_utility_stream_values != NULL )
	{
		libfsntfs_logged_utility_stream_values_free(
		 &logged_utility_stream_values,
		 NULL );
	}
	if( mft_attribute != NULL )
	{
		libfsntfs_mft_attribute_free(
		 &mft_attribute,
		 NULL );
	}
	if( io_handle != NULL )
	{
		libfsntfs_io_handle_free(
		 &io_handle,
		 NULL );
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
	 "libfsntfs_logged_utility_stream_values_initialize",
	 fsntfs_test_logged_utility_stream_values_initialize );

	FSNTFS_TEST_RUN(
	 "libfsntfs_logged_utility_stream_values_free",
	 fsntfs_test_logged_utility_stream_values_free );

	FSNTFS_TEST_RUN(
	 "libfsntfs_logged_utility_stream_values_read_data",
	 fsntfs_test_logged_utility_stream_values_read_data );

	FSNTFS_TEST_RUN(
	 "libfsntfs_logged_utility_stream_values_read_from_mft_attribute",
	 fsntfs_test_logged_utility_stream_values_read_from_mft_attribute );

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

on_error:
	return( EXIT_FAILURE );
}

