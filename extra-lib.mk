# This file is included several times in a row, once
# for each element of $(extra-libs).  $(extra-libs-left)
# is initialized first to $(extra-libs) so that with each
# inclusion, we advance $(lib) to the next library name (e.g. libfoo).
# The variable $($(lib)-routines) defines the list of modules
# to be included in that library.

lib := $(firstword $(extra-libs-left))
extra-libs-left := $(filter-out $(lib),$(extra-libs-left))

# Add each flavor of library to the lists of things to build and install.
install-lib += $(foreach o,$(object-suffixes),$(lib:lib%=$(libtype$o)))
extra-objs += $(foreach o,$(object-suffixes),$($(lib)-routines:=$o))
alltypes-$(lib) = $(foreach o,$(object-suffixes),\
			    $(objpfx)$(patsubst %,$(libtype$o),\
			    $(lib:lib%=%)))
ifeq (yes,$(build-shared))
alltypes-$(lib) += $(objpfx)$(lib).so
endif

lib-noranlib: $(alltypes-$(lib))

# Use o-iterator.mk to generate a rule for each flavor of library.
define o-iterator-doit
$(objpfx)$(patsubst %,$(libtype$o),$(lib:lib%=%)): \
  $($(lib)-routines:%=$(objpfx)%$o); $$(build-extra-lib)
endef
object-suffixes-left := $(filter-out $($(lib)-inhibit-o),$(object-suffixes))
include $(o-iterator)
