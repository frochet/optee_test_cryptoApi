CFG_TEE_TA_LOG_LEVEL ?= 2
CPPFLAGS += -DCFG_TEE_TA_LOG_LEVEL=$(CFG_TEE_TA_LOG_LEVEL)
BINARY=e1ee6b22-560b-11e4-aa8100252221c4f0


include $(TA_DEV_KIT_DIR)/mk/ta_dev_kit.mk

all: $(BINARY).ta

$(BINARY).ta: $(BINARY).bin
	rm -f $@
	cat faked_armv7_uta_signed_header.bin $< > $@

clean: clean_ta_file
.PHONY: clean_ta_file
clean_ta_file:
	rm -f $(BINARY).ta
