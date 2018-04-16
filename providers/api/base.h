/*
 *  libsuola - An engine gluing together OpenSSL and NaCl-derived crypto.
 *  Copyright (C) 2018 TTY Foundation sr
 *
 *  This file is part of libsuola.
 *
 *  libsuola is free software: you can redistribute it and/or modify it under
 *  the terms of the GNU Lesser General Public License as published by the
 *  Free Software Foundation, either version 3 of the License, or (at your
 *  option) any later version.
 *
 *  libsuola is distributed in the hope that it will be useful, but WITHOUT
 *  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 *  FITNESS FOR A PARTICULAR PURPOSE.
 *  See the GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef LIBSUOLA_IMPLEMENTATION_BASE_API_H
#define LIBSUOLA_IMPLEMENTATION_BASE_API_H

/* Initialize implementation backend.
 *
 * This is called during the ENGINE bind() function.
 *
 * Returns 0 on success, non-0 otherwise.
 */
extern int suola_implementation_init(void);

#endif /* ! defined( LIBSUOLA_IMPLEMENTATION_BASE_API_H) */

/* vim: set ts=4 sw=4 tw=78 et : */
