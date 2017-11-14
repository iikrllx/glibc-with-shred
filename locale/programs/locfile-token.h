/* Copyright (C) 1996-2018 Free Software Foundation, Inc.
   This file is part of the GNU C Library.
   Contributed by Ulrich Drepper <drepper@gnu.org>, 1996.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published
   by the Free Software Foundation; version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, see <http://www.gnu.org/licenses/>.  */

#ifndef _TOKEN_H
#define _TOKEN_H

enum token_t
{
  tok_none = 0,

  tok_eof,
  tok_eol,
  tok_bsymbol,
  tok_ident,
  tok_ellipsis2,
  tok_ellipsis3,
  tok_ellipsis4,
  tok_ellipsis2_2,
  tok_ellipsis4_2,
  tok_semicolon,
  tok_comma,
  tok_open_brace,
  tok_close_brace,
  tok_charcode,
  tok_ucs4,
  tok_number,
  tok_minus1,
  tok_string,
  tok_include,

  tok_escape_char,
  tok_comment_char,
  tok_charmap,
  tok_end,
  tok_g0esc,
  tok_g1esc,
  tok_g2esc,
  tok_g3esc,
  tok_escseq,
  tok_addset,

  tok_charids,

  tok_code_set_name,
  tok_mb_cur_max,
  tok_mb_cur_min,
  tok_charconv,
  tok_width,
  tok_width_variable,
  tok_width_default,
  tok_repertoiremap,

  tok_lc_ctype,
  tok_copy,
  /* Keep the following entries up to the next comment in this order!  */
  tok_upper,
  tok_lower,
  tok_alpha,
  tok_digit,
  tok_xdigit,
  tok_space,
  tok_print,
  tok_graph,
  tok_blank,
  tok_cntrl,
  tok_punct,
  tok_alnum,
  /* OK, shuffling allowed again.  */
  tok_outdigit,
  tok_charclass,
  tok_class,
  tok_toupper,
  tok_tolower,
  tok_map,
  tok_translit_start,
  tok_translit_end,
  tok_translit_ignore,
  tok_default_missing,
  tok_lc_collate,
  tok_coll_weight_max,
  tok_section_symbol,
  tok_collating_element,
  tok_collating_symbol,
  tok_symbol_equivalence,
  tok_script,
  tok_order_start,
  tok_order_end,
  tok_from,
  tok_forward,
  tok_backward,
  tok_position,
  tok_undefined,
  tok_ignore,
  tok_reorder_after,
  tok_reorder_end,
  tok_reorder_sections_after,
  tok_reorder_sections_end,
  tok_define,
  tok_undef,
  tok_ifdef,
  tok_ifndef,
  tok_else,
  tok_elifdef,
  tok_elifndef,
  tok_endif,
  tok_lc_monetary,
  tok_int_curr_symbol,
  tok_currency_symbol,
  tok_mon_decimal_point,
  tok_mon_thousands_sep,
  tok_mon_grouping,
  tok_positive_sign,
  tok_negative_sign,
  tok_int_frac_digits,
  tok_frac_digits,
  tok_p_cs_precedes,
  tok_p_sep_by_space,
  tok_n_cs_precedes,
  tok_n_sep_by_space,
  tok_p_sign_posn,
  tok_n_sign_posn,
  tok_int_p_cs_precedes,
  tok_int_p_sep_by_space,
  tok_int_n_cs_precedes,
  tok_int_n_sep_by_space,
  tok_int_p_sign_posn,
  tok_int_n_sign_posn,
  tok_duo_int_curr_symbol,
  tok_duo_currency_symbol,
  tok_duo_int_frac_digits,
  tok_duo_frac_digits,
  tok_duo_p_cs_precedes,
  tok_duo_p_sep_by_space,
  tok_duo_n_cs_precedes,
  tok_duo_n_sep_by_space,
  tok_duo_int_p_cs_precedes,
  tok_duo_int_p_sep_by_space,
  tok_duo_int_n_cs_precedes,
  tok_duo_int_n_sep_by_space,
  tok_duo_p_sign_posn,
  tok_duo_n_sign_posn,
  tok_duo_int_p_sign_posn,
  tok_duo_int_n_sign_posn,
  tok_uno_valid_from,
  tok_uno_valid_to,
  tok_duo_valid_from,
  tok_duo_valid_to,
  tok_conversion_rate,
  tok_lc_numeric,
  tok_decimal_point,
  tok_thousands_sep,
  tok_grouping,
  tok_lc_time,
  tok_abday,
  tok_day,
  tok_abmon,
  tok_mon,
  tok_d_t_fmt,
  tok_d_fmt,
  tok_t_fmt,
  tok_am_pm,
  tok_t_fmt_ampm,
  tok_era,
  tok_era_year,
  tok_era_d_fmt,
  tok_era_d_t_fmt,
  tok_era_t_fmt,
  tok_alt_digits,
  tok_week,
  tok_first_weekday,
  tok_first_workday,
  tok_cal_direction,
  tok_timezone,
  tok_date_fmt,
  tok_alt_mon,
  tok_ab_alt_mon,
  tok_lc_messages,
  tok_yesexpr,
  tok_noexpr,
  tok_yesstr,
  tok_nostr,
  tok_lc_paper,
  tok_height,
  tok_lc_name,
  tok_name_fmt,
  tok_name_gen,
  tok_name_mr,
  tok_name_mrs,
  tok_name_miss,
  tok_name_ms,
  tok_lc_address,
  tok_postal_fmt,
  tok_country_name,
  tok_country_post,
  tok_country_ab2,
  tok_country_ab3,
  tok_country_num,
  tok_country_car,
  tok_country_isbn,
  tok_lang_name,
  tok_lang_ab,
  tok_lang_term,
  tok_lang_lib,
  tok_lc_telephone,
  tok_tel_int_fmt,
  tok_tel_dom_fmt,
  tok_int_select,
  tok_int_prefix,
  tok_lc_measurement,
  tok_measurement,
  tok_lc_identification,
  tok_title,
  tok_source,
  tok_address,
  tok_contact,
  tok_email,
  tok_tel,
  tok_fax,
  tok_language,
  tok_territory,
  tok_audience,
  tok_application,
  tok_abbreviation,
  tok_revision,
  tok_date,
  tok_category,

  tok_error
};


struct keyword_t
{
  const char *name;
  enum token_t token;
  int symname_or_ident;

  /* Only for locdef file.  */
  int locale;
  enum token_t base;
  enum token_t group;
  enum token_t list;
};


#endif /* token.h */
