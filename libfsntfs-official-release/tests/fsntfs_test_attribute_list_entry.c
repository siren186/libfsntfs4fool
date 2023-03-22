/*
 * Library attribute_list_entry type test program
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

#include "../libfsntfs/libfsntfs_attribute_list_entry.h"

uint8_t fsntfs_test_attribute_list_entry_data1[ 40 ] = {
	0x80, 0x00, 0x00, 0x00, 0x28, 0x00, 0x04, 0x1a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xc8, 0x08, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x24, 0x00, 0x53, 0x00, 0x44, 0x00,
	0x53, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

/* Tests the libfsntfs_attribute_list_entry_initialize function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_attribute_list_entry_initialize(
     void )
{
	libcerror_error_t *error                                       = NULL;
	libfsntfs_attribute_list_entry_t *attribute_list_entry         = NULL;
	libfsntfs_mft_attribute_list_entry_t *mft_attribute_list_entry = NULL;
	int result                                                     = 0;

#if defined( HAVE_FSNTFS_TEST_MEMORY )
	int number_of_malloc_fail_tests                                = 1;
	int number_of_memset_fail_tests                                = 1;
	int test_number                                                = 0;
#endif

	/* Initialize test
	 */
	result = libfsntfs_mft_attribute_list_entry_initialize(
	          &mft_attribute_list_entry,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "mft_attribute_list_entry",
	 mft_attribute_list_entry );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test regular cases
	 */
	result = libfsntfs_attribute_list_entry_initialize(
	          &attribute_list_entry,
	          mft_attribute_list_entry,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "attribute_list_entry",
	 attribute_list_entry );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_attribute_list_entry_free(
	          &attribute_list_entry,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "attribute_list_entry",
	 attribute_list_entry );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Test error cases
	 */
	result = libfsntfs_attribute_list_entry_initialize(
	          NULL,
	          mft_attribute_list_entry,
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

	attribute_list_entry = (libfsntfs_attribute_list_entry_t *) 0x12345678UL;

	result = libfsntfs_attribute_list_entry_initialize(
	          &attribute_list_entry,
	          mft_attribute_list_entry,
	          &error );

	attribute_list_entry = NULL;

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	result = libfsntfs_attribute_list_entry_initialize(
	          &attribute_list_entry,
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

#if defined( HAVE_FSNTFS_TEST_MEMORY )

	for( test_number = 0;
	     test_number < number_of_malloc_fail_tests;
	     test_number++ )
	{
		/* Test libfsntfs_attribute_list_entry_initialize with malloc failing
		 */
		fsntfs_test_malloc_attempts_before_fail = test_number;

		result = libfsntfs_attribute_list_entry_initialize(
		          &attribute_list_entry,
		          mft_attribute_list_entry,
		          &error );

		if( fsntfs_test_malloc_attempts_before_fail != -1 )
		{
			fsntfs_test_malloc_attempts_before_fail = -1;

			if( attribute_list_entry != NULL )
			{
				libfsntfs_attribute_list_entry_free(
				 &attribute_list_entry,
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
			 "attribute_list_entry",
			 attribute_list_entry );

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
		/* Test libfsntfs_attribute_list_entry_initialize with memset failing
		 */
		fsntfs_test_memset_attempts_before_fail = test_number;

		result = libfsntfs_attribute_list_entry_initialize(
		          &attribute_list_entry,
		          mft_attribute_list_entry,
		          &error );

		if( fsntfs_test_memset_attempts_before_fail != -1 )
		{
			fsntfs_test_memset_attempts_before_fail = -1;

			if( attribute_list_entry != NULL )
			{
				libfsntfs_attribute_list_entry_free(
				 &attribute_list_entry,
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
			 "attribute_list_entry",
			 attribute_list_entry );

			FSNTFS_TEST_ASSERT_IS_NOT_NULL(
			 "error",
			 error );

			libcerror_error_free(
			 &error );
		}
	}
#endif /* defined( HAVE_FSNTFS_TEST_MEMORY ) */

	/* Clean up
	 */
	result = libfsntfs_mft_attribute_list_entry_free(
	          &mft_attribute_list_entry,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "mft_attribute_list_entry",
	 mft_attribute_list_entry );

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
	if( attribute_list_entry != NULL )
	{
		libfsntfs_attribute_list_entry_free(
		 &attribute_list_entry,
		 NULL );
	}
	if( mft_attribute_list_entry != NULL )
	{
		libfsntfs_mft_attribute_list_entry_free(
		 &mft_attribute_list_entry,
		 NULL );
	}
	return( 0 );
}

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

/* Tests the libfsntfs_attribute_list_entry_free function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_attribute_list_entry_free(
     void )
{
	libcerror_error_t *error = NULL;
	int result               = 0;

	/* Test error cases
	 */
	result = libfsntfs_attribute_list_entry_free(
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

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

/* Tests the libfsntfs_attribute_list_entry_get_attribute_type function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_attribute_list_entry_get_attribute_type(
     libfsntfs_attribute_list_entry_t *attribute_list_entry )
{
	libcerror_error_t *error                                       = NULL;
	libfsntfs_mft_attribute_list_entry_t *mft_attribute_list_entry = NULL;
	uint32_t attribute_type                                        = 0;
	int result                                                     = 0;

	/* Test regular cases
	 */
	result = libfsntfs_attribute_list_entry_get_attribute_type(
	          attribute_list_entry,
	          &attribute_type,
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
	result = libfsntfs_attribute_list_entry_get_attribute_type(
	          NULL,
	          &attribute_type,
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

	result = libfsntfs_attribute_list_entry_get_attribute_type(
	          attribute_list_entry,
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
	if( mft_attribute_list_entry != NULL )
	{
		libfsntfs_mft_attribute_list_entry_free(
		 &mft_attribute_list_entry,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_attribute_list_entry_get_file_reference function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_attribute_list_entry_get_file_reference(
     libfsntfs_attribute_list_entry_t *attribute_list_entry )
{
	libcerror_error_t *error                                       = NULL;
	libfsntfs_mft_attribute_list_entry_t *mft_attribute_list_entry = NULL;
	uint64_t file_reference                                        = 0;
	int result                                                     = 0;

	/* Test regular cases
	 */
	result = libfsntfs_attribute_list_entry_get_file_reference(
	          attribute_list_entry,
	          &file_reference,
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
	result = libfsntfs_attribute_list_entry_get_file_reference(
	          NULL,
	          &file_reference,
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

	result = libfsntfs_attribute_list_entry_get_file_reference(
	          attribute_list_entry,
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
	if( mft_attribute_list_entry != NULL )
	{
		libfsntfs_mft_attribute_list_entry_free(
		 &mft_attribute_list_entry,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_attribute_list_entry_get_utf8_name_size function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_attribute_list_entry_get_utf8_name_size(
     libfsntfs_attribute_list_entry_t *attribute_list_entry )
{
	libcerror_error_t *error                                       = NULL;
	libfsntfs_mft_attribute_list_entry_t *mft_attribute_list_entry = NULL;
	size_t utf8_string_size                                        = 0;
	int result                                                     = 0;

	/* Test regular cases
	 */
	result = libfsntfs_attribute_list_entry_get_utf8_name_size(
	          attribute_list_entry,
	          &utf8_string_size,
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
	result = libfsntfs_attribute_list_entry_get_utf8_name_size(
	          NULL,
	          &utf8_string_size,
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

	result = libfsntfs_attribute_list_entry_get_utf8_name_size(
	          attribute_list_entry,
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
	if( mft_attribute_list_entry != NULL )
	{
		libfsntfs_mft_attribute_list_entry_free(
		 &mft_attribute_list_entry,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_attribute_list_entry_get_utf8_name function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_attribute_list_entry_get_utf8_name(
     libfsntfs_attribute_list_entry_t *attribute_list_entry )
{
	uint8_t utf8_string[ 512 ];

	libcerror_error_t *error                                       = NULL;
	libfsntfs_mft_attribute_list_entry_t *mft_attribute_list_entry = NULL;
	int result                                                     = 0;

	/* Test regular cases
	 */
	result = libfsntfs_attribute_list_entry_get_utf8_name(
	          attribute_list_entry,
	          utf8_string,
	          512,
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
	result = libfsntfs_attribute_list_entry_get_utf8_name(
	          NULL,
	          utf8_string,
	          512,
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

	result = libfsntfs_attribute_list_entry_get_utf8_name(
	          attribute_list_entry,
	          NULL,
	          512,
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

	result = libfsntfs_attribute_list_entry_get_utf8_name(
	          attribute_list_entry,
	          utf8_string,
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

	result = libfsntfs_attribute_list_entry_get_utf8_name(
	          attribute_list_entry,
	          utf8_string,
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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( mft_attribute_list_entry != NULL )
	{
		libfsntfs_mft_attribute_list_entry_free(
		 &mft_attribute_list_entry,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_attribute_list_entry_get_utf16_name_size function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_attribute_list_entry_get_utf16_name_size(
     libfsntfs_attribute_list_entry_t *attribute_list_entry )
{
	libcerror_error_t *error                                       = NULL;
	libfsntfs_mft_attribute_list_entry_t *mft_attribute_list_entry = NULL;
	size_t utf16_string_size                                       = 0;
	int result                                                     = 0;

	/* Test regular cases
	 */
	result = libfsntfs_attribute_list_entry_get_utf16_name_size(
	          attribute_list_entry,
	          &utf16_string_size,
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
	result = libfsntfs_attribute_list_entry_get_utf16_name_size(
	          NULL,
	          &utf16_string_size,
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

	result = libfsntfs_attribute_list_entry_get_utf16_name_size(
	          attribute_list_entry,
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
	if( mft_attribute_list_entry != NULL )
	{
		libfsntfs_mft_attribute_list_entry_free(
		 &mft_attribute_list_entry,
		 NULL );
	}
	return( 0 );
}

/* Tests the libfsntfs_attribute_list_entry_get_utf16_name function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_attribute_list_entry_get_utf16_name(
     libfsntfs_attribute_list_entry_t *attribute_list_entry )
{
	uint16_t utf16_string[ 512 ];

	libcerror_error_t *error                                       = NULL;
	libfsntfs_mft_attribute_list_entry_t *mft_attribute_list_entry = NULL;
	int result                                                     = 0;

	/* Test regular cases
	 */
	result = libfsntfs_attribute_list_entry_get_utf16_name(
	          attribute_list_entry,
	          utf16_string,
	          512,
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
	result = libfsntfs_attribute_list_entry_get_utf16_name(
	          NULL,
	          utf16_string,
	          512,
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

	result = libfsntfs_attribute_list_entry_get_utf16_name(
	          attribute_list_entry,
	          NULL,
	          512,
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

	result = libfsntfs_attribute_list_entry_get_utf16_name(
	          attribute_list_entry,
	          utf16_string,
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

	result = libfsntfs_attribute_list_entry_get_utf16_name(
	          attribute_list_entry,
	          utf16_string,
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

	return( 1 );

on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( mft_attribute_list_entry != NULL )
	{
		libfsntfs_mft_attribute_list_entry_free(
		 &mft_attribute_list_entry,
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
#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )
	libcerror_error_t *error                                       = NULL;
	libfsntfs_attribute_list_entry_t *attribute_list_entry         = NULL;
	libfsntfs_mft_attribute_list_entry_t *mft_attribute_list_entry = NULL;
	int result                                                     = 0;
#endif

	FSNTFS_TEST_UNREFERENCED_PARAMETER( argc )
	FSNTFS_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

	FSNTFS_TEST_RUN(
	 "libfsntfs_attribute_list_entry_initialize",
	 fsntfs_test_attribute_list_entry_initialize );

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

	FSNTFS_TEST_RUN(
	 "libfsntfs_attribute_list_entry_free",
	 fsntfs_test_attribute_list_entry_free );

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	/* Initialize attribute_list_entry for tests
	 */
	result = libfsntfs_mft_attribute_list_entry_initialize(
	          &mft_attribute_list_entry,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "mft_attribute_list_entry",
	 mft_attribute_list_entry );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_mft_attribute_list_entry_read_data(
	          mft_attribute_list_entry,
	          fsntfs_test_attribute_list_entry_data1,
	          40,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_attribute_list_entry_initialize(
	          &attribute_list_entry,
	          mft_attribute_list_entry,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "attribute_list_entry",
	 attribute_list_entry );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	/* Run tests
	 */
	FSNTFS_TEST_RUN_WITH_ARGS(
	 "libfsntfs_attribute_list_entry_get_attribute_type",
	 fsntfs_test_attribute_list_entry_get_attribute_type,
	 attribute_list_entry );

	FSNTFS_TEST_RUN_WITH_ARGS(
	 "libfsntfs_attribute_list_entry_get_file_reference",
	 fsntfs_test_attribute_list_entry_get_file_reference,
	 attribute_list_entry );

	FSNTFS_TEST_RUN_WITH_ARGS(
	 "libfsntfs_attribute_list_entry_get_utf8_name_size",
	 fsntfs_test_attribute_list_entry_get_utf8_name_size,
	 attribute_list_entry );

	FSNTFS_TEST_RUN_WITH_ARGS(
	 "libfsntfs_attribute_list_entry_get_utf8_name",
	 fsntfs_test_attribute_list_entry_get_utf8_name,
	 attribute_list_entry );

	FSNTFS_TEST_RUN_WITH_ARGS(
	 "libfsntfs_attribute_list_entry_get_utf16_name_size",
	 fsntfs_test_attribute_list_entry_get_utf16_name_size,
	 attribute_list_entry );

	FSNTFS_TEST_RUN_WITH_ARGS(
	 "libfsntfs_attribute_list_entry_get_utf16_name",
	 fsntfs_test_attribute_list_entry_get_utf16_name,
	 attribute_list_entry );

	/* Clean up
	 */
	result = libfsntfs_attribute_list_entry_free(
	          &attribute_list_entry,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "attribute_list_entry",
	 attribute_list_entry );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_mft_attribute_list_entry_free(
	          &mft_attribute_list_entry,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "mft_attribute_list_entry",
	 mft_attribute_list_entry );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

on_error:
#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( attribute_list_entry != NULL )
	{
		libfsntfs_attribute_list_entry_free(
		 &attribute_list_entry,
		 NULL );
	}
	if( mft_attribute_list_entry != NULL )
	{
		libfsntfs_mft_attribute_list_entry_free(
		 &mft_attribute_list_entry,
		 NULL );
	}
#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

	return( EXIT_FAILURE );
}

