ifeq ($(CONFIG_OF_CONFIGFS),y)

dtbo-$(CONFIG_MACH_SUN8I) += \
	sun8i-h3-analog-codec.dtbo \
	sun8i-h3-crypto.dtbo \
	sun8i-h3-i2c0.dtbo \
	sun8i-h3-spi0-spidev.dtbo \
	sun8i-h3-spi1-spidev.dtbo \
	sun8i-h3-uart1.dtbo \
	sun8i-h3-uart2.dtbo \
	sun8i-h3-uart3.dtbo \
	sun8i-h3-usbhost0.dtbo \
	sun8i-h3-usbhost2.dtbo \
	sun8i-h3-usbhost3.dtbo \
	sun8i-h3-w1.dtbo

targets += dtbs dtbs_install
targets += $(dtbo-y)

endif

always		:= $(dtbo-y)
