/*
 * Library volume_information_attributes functions test program
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

#include "../libfsntfs/libfsntfs_attribute.h"
#include "../libfsntfs/libfsntfs_io_handle.h"
#include "../libfsntfs/libfsntfs_volume_information_attribute.h"

uint8_t fsntfs_test_volume_information_attribute_data1[ 40 ] = {
	0x70, 0x00, 0x00, 0x00, 0x28, 0x00, 0x00, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x05, 0x00,
	0x0c, 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x03, 0x01, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00 };

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

/* Tests the libfsntfs_volume_information_attribute_get_version function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_volume_information_attribute_get_version(
     libfsntfs_attribute_t *attribute )
{
	libcerror_error_t *error = NULL;
	intptr_t *value          = NULL;
	uint32_t type            = 0;
	uint8_t major_version    = 0;
	uint8_t minor_version    = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = libfsntfs_volume_information_attribute_get_version(
	          attribute,
	          &major_version,
	          &minor_version,
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
	result = libfsntfs_volume_information_attribute_get_version(
	          NULL,
	          &major_version,
	          &minor_version,
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

	result = libfsntfs_volume_information_attribute_get_version(
	          attribute,
	          NULL,
	          &minor_version,
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

	result = libfsntfs_volume_information_attribute_get_version(
	          attribute,
	          &major_version,
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

	type = ( (libfsntfs_internal_attribute_t *) attribute )->mft_attribute->type;

	( (libfsntfs_internal_attribute_t *) attribute )->mft_attribute->type = 0;

	result = libfsntfs_volume_information_attribute_get_version(
	          attribute,
	          &major_version,
	          &minor_version,
	          &error );

	( (libfsntfs_internal_attribute_t *) attribute )->mft_attribute->type = type;

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	value = ( (libfsntfs_internal_attribute_t *) attribute )->value;

	( (libfsntfs_internal_attribute_t *) attribute )->value = NULL;

	result = libfsntfs_volume_information_attribute_get_version(
	          attribute,
	          &major_version,
	          &minor_version,
	          &error );

	( (libfsntfs_internal_attribute_t *) attribute )->value = value;

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

/* Tests the libfsntfs_volume_information_attribute_get_flags function
 * Returns 1 if successful or 0 if not
 */
int fsntfs_test_volume_information_attribute_get_flags(
     libfsntfs_attribute_t *attribute )
{
	libcerror_error_t *error = NULL;
	intptr_t *value          = NULL;
	uint32_t type            = 0;
	uint16_t flags           = 0;
	int result               = 0;

	/* Test regular cases
	 */
	result = libfsntfs_volume_information_attribute_get_flags(
	          attribute,
	          &flags,
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
	result = libfsntfs_volume_information_attribute_get_flags(
	          NULL,
	          &flags,
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

	result = libfsntfs_volume_information_attribute_get_flags(
	          attribute,
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

	type = ( (libfsntfs_internal_attribute_t *) attribute )->mft_attribute->type;

	( (libfsntfs_internal_attribute_t *) attribute )->mft_attribute->type = 0;

	result = libfsntfs_volume_information_attribute_get_flags(
	          attribute,
	          &flags,
	          &error );

	( (libfsntfs_internal_attribute_t *) attribute )->mft_attribute->type = type;

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 -1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "error",
	 error );

	libcerror_error_free(
	 &error );

	value = ( (libfsntfs_internal_attribute_t *) attribute )->value;

	( (libfsntfs_internal_attribute_t *) attribute )->value = NULL;

	result = libfsntfs_volume_information_attribute_get_flags(
	          attribute,
	          &flags,
	          &error );

	( (libfsntfs_internal_attribute_t *) attribute )->value = value;

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
#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )
	libcerror_error_t *error                 = NULL;
	libfsntfs_attribute_t *attribute         = NULL;
	libfsntfs_io_handle_t *io_handle         = NULL;
	libfsntfs_mft_attribute_t *mft_attribute = NULL;
	int result                               = 0;
#endif

	FSNTFS_TEST_UNREFERENCED_PARAMETER( argc )
	FSNTFS_TEST_UNREFERENCED_PARAMETER( argv )

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )

#if !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 )

	/* Initialize attribute for tests
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
	          fsntfs_test_volume_information_attribute_data1,
	          40,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_attribute_initialize(
	          &attribute,
	          mft_attribute,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NOT_NULL(
	 "attribute",
	 attribute );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	result = libfsntfs_internal_attribute_read_value(
	          (libfsntfs_internal_attribute_t *) attribute,
	          io_handle,
	          NULL,
	          0,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "error",
	 error );

	FSNTFS_TEST_RUN_WITH_ARGS(
	 "libfsntfs_volume_information_attribute_get_version",
	 fsntfs_test_volume_information_attribute_get_version,
	 attribute );

	FSNTFS_TEST_RUN_WITH_ARGS(
	 "libfsntfs_volume_information_attribute_get_flags",
	 fsntfs_test_volume_information_attribute_get_flags,
	 attribute );

	/* Clean up
	 */
	result = libfsntfs_internal_attribute_free(
	          (libfsntfs_internal_attribute_t **) &attribute,
	          &error );

	FSNTFS_TEST_ASSERT_EQUAL_INT(
	 "result",
	 result,
	 1 );

	FSNTFS_TEST_ASSERT_IS_NULL(
	 "attribute",
	 attribute );

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

#endif /* !defined( __BORLANDC__ ) || ( __BORLANDC__ >= 0x0560 ) */

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */

	return( EXIT_SUCCESS );

#if defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT )
on_error:
	if( error != NULL )
	{
		libcerror_error_free(
		 &error );
	}
	if( attribute != NULL )
	{
		libfsntfs_internal_attribute_free(
	         (libfsntfs_internal_attribute_t **) &attribute,
	         &error );
	}
	if( mft_attribute != NULL )
	{
		libfsntfs_mft_attribute_free(
	         &mft_attribute,
	         &error );
	}
	if( io_handle != NULL )
	{
		libfsntfs_io_handle_free(
		 &io_handle,
		 NULL );
	}
	return( EXIT_FAILURE );

#endif /* defined( __GNUC__ ) && !defined( LIBFSNTFS_DLL_IMPORT ) */
}

