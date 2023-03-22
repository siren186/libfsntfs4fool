/*
 * Index node header functions
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

#if !defined( _LIBFSNTFS_INDEX_NODE_HEADER_H )
#define _LIBFSNTFS_INDEX_NODE_HEADER_H

#include <common.h>
#include <types.h>

#include "libfsntfs_libcerror.h"

#if defined( __cplusplus )
extern "C" {
#endif

typedef struct libfsntfs_index_node_header libfsntfs_index_node_header_t;

struct libfsntfs_index_node_header
{
	/* The size
	 */
	uint32_t size;

	/* The index values offset
	 */
	uint32_t index_values_offset;

	/* The flags
	 */
	uint32_t flags;
};

int libfsntfs_index_node_header_initialize(
     libfsntfs_index_node_header_t **index_node_header,
     libcerror_error_t **error );

int libfsntfs_index_node_header_free(
     libfsntfs_index_node_header_t **index_node_header,
     libcerror_error_t **error );

int libfsntfs_index_node_header_read_data(
     libfsntfs_index_node_header_t *index_node_header,
     const uint8_t *data,
     size_t data_size,
     libcerror_error_t **error );

#if defined( __cplusplus )
}
#endif

#endif /* !defined( _LIBFSNTFS_INDEX_NODE_HEADER_H ) */

