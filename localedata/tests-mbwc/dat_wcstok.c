/*
 *  TEST SUITE FOR MB/WC FUNCTIONS IN CLIBRARY
 *
 *	 FILE:	dat_wcstok.c
 *
 *	 WCSTOK: wchar_t *wcstok (wchar_t *ws, const wchar_t *dlm,
 *				  wchar_t **pt);
 */

/*
 *  NOTE:
 *	  need more test data!
 *	  locale insensitive function...
 */




TST_WCSTOK tst_wcstok_loc [] = {
  {
    { Twcstok, TST_LOC_de },
    {
      {
	{
	  {
	    { 1, { 0x00D1,0x00D2,0x00D3,0x00D4,0x00D5,0x00D6,0x00D7,0x00D8,
		   0x00D9,0x0000 },
	      {	       0x00D3,0x00D2,	    0x00D5 }
	    },
	    { 0, { 0x00D1,0x00D2,0x00D3,0x00D4,0x00D5,0x00D6,0x00D7,0x00D8,
		   0x00D9,0x0000 },
	      {	       0x00D3,0x00D2,	    0x00D5 }
	    },
	    { 0, { 0x00D1,0x00D2,0x00D3,0x00D4,0x00D5,0x00D6,0x00D7,0x00D8,
		   0x00D9,0x0000 },
	      {	       0x00D3,0x00D2,	    0x00D5 }
	    },
	  }
	},
	{
	  {
	    { 0, 0,0,
	      { 0x00D1,0x0000 }
	    },
	    { 0, 0,0,
	      {			     0x00D4,0x0000 }
	    },
	    { 0, 0,0,
	      { 0x00D6,0x00D7,0x00D8,0x00D9,0x0000 }
	    },
	  }
	}
      },
      { .is_last = 1 }
    }
  },
  {
    { Twcstok, TST_LOC_enUS },
    {
      {
	{
	  {
	    { 1, { 0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,
		   0x0049,0x0000 },
	      {	       0x0043,0x0042,	    0x0045 }
	    },
	    { 0, { 0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,
		   0x0049,0x0000 },
	      {	       0x0043,0x0042,	    0x0045 }
	    },
	    { 0, { 0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,
		   0x0049,0x0000 },
	      {	       0x0043,0x0042,	    0x0045 }
	    },
	  }
	},
	{
	  {
	    { 0, 0,0,
	      { 0x0041,0x0000 }
	    },
	    { 0, 0,0,
	      {			     0x0044,0x0000 }
	    },
	    { 0, 0,0,
	      { 0x0046,0x0047,0x0048,0x0049,0x0000 }
	    },
	  }
	}
      },
      { .is_last = 1 }
    }
  },
  {
    { Twcstok, TST_LOC_eucJP },
    {
      {
	{
	  {
	    { 1, { 0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,
		   0x0049,0x0000 },
	      {	       0x0043,0x0042,	    0x0045 }
	    },
	    { 0, { 0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,
		   0x0049,0x0000 },
	      {	       0x0043,0x0042,	    0x0045 }
	    },
	    { 0, { 0x0041,0x0042,0x0043,0x0044,0x0045,0x0046,0x0047,0x0048,
		   0x0049,0x0000 },
	      {	       0x0043,0x0042,	    0x0045 }
	    },
	  }
	},
	{
	  {
	    { 0, 0,0,
	      { 0x0041,0x0000 }
	    },
	    { 0, 0,0,
	      {			     0x0044,0x0000 }
	    },
	    { 0, 0,0,
	      { 0x0046,0x0047,0x0048,0x0049,0x0000 }
	    },
	  }
	}
      },
      { .is_last = 1 }
    }
  },
  {
    { Twcstok, TST_LOC_end }
  }
};
