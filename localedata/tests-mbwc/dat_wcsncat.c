/*
 *  TEST SUITE FOR MB/WC FUNCTIONS IN C LIBRARY
 *
 *	 FILE:	dat_wcsncat.c
 *
 *	 WCSNCAT:  wchar_t *wcsncat (wchar_t *ws1, wchar_t *ws2, size_t n);
 */


/*
 *  Note:
 *	  A terminating null wide chararacter is always appended to
 *	  the result: ws1.
 *
 */


TST_WCSNCAT tst_wcsncat_loc [] = {
  {
    {Twcsncat, TST_LOC_de},
    {
      /* 1 */
      {
	/* Input: */
	{{ 0x00D1,0x00D2,0x0000	 },
	 {		    0x00D3,0x00D4,0x0000 }, 3 },
	/* Expect: */
	{   0,	0,    0,
	    { 0x00D1,0x00D2,0x00D3,0x00D4,0x0000 }    },
      },
      /* 2 */
      {{{ 0x00D1,0x00D2,0x0000	},
	{		   0x00D3,0x00D4,0x0000 }, 2 },
       {   0,    0,    0,
	   { 0x00D1,0x00D2,0x00D3,0x00D4,0x0000 }    },
      },
      /* 3 */
      {{{ 0x00E1,0x00E2,0x0000	},
	{		   0x00E3,0x00E4,0x0000 }, 1 },
       {   0,    0,    0,
	   { 0x00E1,0x00E2,0x00E3,0x0000	}    },
      },
      /* 4 */
      {{{ 0x00E1,0x00E2,0x0000	},
	{		   0x00E3,0x00E4,0x0000 }, 0 },
       {   0,    0,    0,
	   { 0x00E1,0x00E2,0x0000		}    },
      },
      /* 5 */
      {{{ 0x0000		},
	{		   0x00D3,0x00D4,0x0000 }, 3 },
       {   0,    0,    0,
	   {		   0x00D3,0x00D4,0x0000 }    },
      },
      /* 6 */
      {{{ 0x00E1,0x00E2,0x0000	},
	{		   0x0000		}, 3 },
       {   0,    0,    0,
	   { 0x00E1,0x00E2,0x0000		}    },
      },
      {is_last: 1}
    }
  },
  {
    {Twcsncat, TST_LOC_enUS},
    {
      /* 1 */
      {
	/* Input:  */
	{{ 0x0041,0x0042,0x0000	 },
	 {		    0x0043,0x0044,0x0000 }, 3 },
	/* Expect:  */
	{   0,	0,    0,
	    { 0x0041,0x0042,0x0043,0x0044,0x0000 }    },
      },
      /* 2 */
      {{{ 0x0041,0x0042,0x0000	},
	{		   0x0043,0x0044,0x0000 }, 2 },
       {   0,    0,    0,
	   { 0x0041,0x0042,0x0043,0x0044,0x0000 }    },
      },
      /* 3 */
      {{{ 0x0051,0x0052,0x0000	},
	{		   0x0053,0x0054,0x0000 }, 1 },
       {   0,    0,    0,
	   { 0x0051,0x0052,0x0053,0x0000	}    },
      },
      /* 4 */
      {{{ 0x0051,0x0052,0x0000	},
	{		   0x0053,0x0054,0x0000 }, 0 },
       {   0,    0,    0,
	   { 0x0051,0x0052,0x0000		}    },
      },
      /* 5 */
      {{{ 0x0000		},
	{		   0x0043,0x0044,0x0000 }, 3 },
       {   0,    0,    0,
	   {		   0x0043,0x0044,0x0000 }    },
      },
      /* 6 */
      {{{ 0x0051,0x0052,0x0000	},
	{		   0x0000		}, 3 },
       {   0,    0,    0,
	   { 0x0051,0x0052,0x0000		}    },
      },
      {is_last: 1}
    }
  },
  {
    {Twcsncat, TST_LOC_eucJP},
    {
      /* 1 */
      {{{ 0x3041,0x3042,0x0000	},
	{		   0x3043,0x3044,0x0000 }, 3 },
       {   0,    0,    0,
	   { 0x3041,0x3042,0x3043,0x3044,0x0000 }    },
      },
      /* 2 */
      {{{ 0x30A2,0x30A3,0x0000	},
	{		   0xFF71,0xFF72,0x0000 }, 2 },
       {   0,    0,    0,
	   { 0x30A2,0x30A3,0xFF71,0xFF72,0x0000 }    },
      },
      /* 3 */
      {{{ 0x3051,0x3052,0x0000	},
	{		   0x3053,0x3054,0x0000 }, 1 },
       {   0,    0,    0,
	   { 0x3051,0x3052,0x3053,0x0000	}    },
      },
      /* 4 */
      {{{ 0x3051,0x3052,0x0000	},
	{		   0x3053,0x3054,0x0000 }, 0 },
       {   0,    0,    0,
	   { 0x3051,0x3052,0x0000		}    },
      },
      /* 5 */
      {{{ 0x0000		},
	{		   0x3043,0x3044,0x0000 }, 3 },
       {   0,    0,    0,
	   {		   0x3043,0x3044,0x0000 }    },
      },
      /* 6 */
      {{{ 0x3051,0x3052,0x0000	},
	{		   0x0000		}, 3 },
       {   0,    0,    0,
	   { 0x3051,0x3052,0x0000		}    },
      },
      {is_last: 1}
    }
  },
  {
    {Twcsncat, TST_LOC_end}
  }
};
