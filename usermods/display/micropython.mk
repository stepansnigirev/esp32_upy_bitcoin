DISPLAY_MOD_DIR := $(USERMOD_DIR)

# Add all C files to SRC_USERMOD.
SRC_USERMOD += $(DISPLAY_MOD_DIR)/moddisplay.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/moddisplay_tft.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/comic24.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/def_small.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/DejaVuSans24.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/SmallFont.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/tft.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/tftspi.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/tooney32.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/Ubuntu16.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/minya24.c
SRC_USERMOD += $(DISPLAY_MOD_DIR)/tft/DefaultFont.c

# We can add our module folder to include paths if needed
CFLAGS_USERMOD += -I$(DISPLAY_MOD_DIR)/tft

