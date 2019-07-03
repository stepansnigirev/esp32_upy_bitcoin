
# This file is part of MicroPython M5Stack package
# Copyright (c) 2017 Mika Tuupola
#
# Licensed under the MIT license:
#   http://www.opensource.org/licenses/mit-license.php
#
# Project home:
#   https://github.com/tuupola/micropython-m5stacj

from machine import Pin, SPI
from . import ili934
from .ili934 import color565
from . import pins

class LCD(ili934.ILI9341):
    def __init__(self):
        self.power = Pin(pins.TFT_LED_PIN, Pin.OUT)
        self.power.value(1)
        spi = SPI(2, baudrate=40000000, miso=Pin(pins.TFT_MISO_PIN), mosi=Pin(pins.TFT_MOSI_PIN), sck=Pin(pins.TFT_CLK_PIN))
        cs=Pin(pins.TFT_CS_PIN)
        dc=Pin(pins.TFT_DC_PIN)
        rst=Pin(pins.TFT_RST_PIN)
        super().__init__(spi, cs, dc, rst)

    def off(self):
        self.power.value(0)

    def on(self):
        self.power.value(1)