
export V?=0

.PHONY: all
all:
	make -C client CROSS_COMPILE=$(HOST_CROSS_COMPILE)
	make -C ta CROSS_COMPILE=$(TA_CROSS_COMPILE)

.PHONY: clean
clean:
	make -C client clean
	make -C ta clean
	
