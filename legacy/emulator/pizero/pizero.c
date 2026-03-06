/*
 * Copyright (C) 2018-2025 Yannick Heneault <yheneaul@gmail.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <SDL.h>

#include <bcm2835.h>

#include "pizero.h"
#include "buttons.h"
#include "rng.h"
#include "oled_drivers.h"

#define RANDOM_DEV_FILE "/dev/random"

static uint8_t gpio_yes;
static uint8_t gpio_no;
static uint8_t oled_type = 0;
static int random_fd = -1;

static uint8_t buttonPin(const char* pinVarName, uint8_t defaultPin) {
	int pin = defaultPin;
	const char *variable = getenv(pinVarName);
	if (variable != NULL) {
		int gpio = atoi(variable);
		if (gpio >= 1 && pin <=27) {
			pin = gpio;
		} else {
			fprintf(stderr, "Invalid value in config file for %s. Must be between 1 and 27.\n", pinVarName);
			exit(1);
		}
	}

	return pin;
}

void pizeroInit(void) {
	bcm2835_init();
	gpio_yes = buttonPin("TREZOR_GPIO_YES", 16);
	bcm2835_gpio_fsel(gpio_yes, BCM2835_GPIO_FSEL_INPT);
	bcm2835_gpio_set_pud(gpio_yes, BCM2835_GPIO_PUD_UP );
	gpio_no = buttonPin("TREZOR_GPIO_NO", 12);
	bcm2835_gpio_fsel(gpio_no, BCM2835_GPIO_FSEL_INPT);
	bcm2835_gpio_set_pud(gpio_no, BCM2835_GPIO_PUD_UP );

	//output on oled if configured also
	if (getenv("TREZOR_OLED_TYPE")) {
		oled_type = atoi(getenv("TREZOR_OLED_TYPE"));
		bool flip = atoi(getenv("TREZOR_OLED_FLIP")) ? true : false;

		if (oled_type > 0 && oled_type < OLED_LAST_OLED) {
			bool init_done = oled_init(oled_type, flip);
			if (!init_done) {
				fprintf(stderr, "Failed to initialize oled");
				exit(1);
			}
		}
	}
}

void pizeroRefresh(const uint8_t *buffer) {
	if (oled_type > 0 && oled_type < OLED_LAST_OLED) {
		oled_display(buffer);
	}
}

uint16_t buttonRead(void) {
	uint16_t state = 0;

	const uint8_t *scancodes = SDL_GetKeyboardState(NULL);

	if (scancodes[SDL_SCANCODE_LEFT] || bcm2835_gpio_lev(gpio_no) == 0) {
		state |= BTN_PIN_NO;
	}

	if (scancodes[SDL_SCANCODE_RIGHT] || bcm2835_gpio_lev(gpio_yes) == 0) {
		state |= BTN_PIN_YES;
	}

	return ~state;
}

void random_buffer(uint8_t *buf, size_t len) {
    static uint8_t last_byte = 0;
    uint8_t new_byte = 0;

    if (random_fd == -1) {
        random_fd = open(RANDOM_DEV_FILE, O_RDONLY);
        if (random_fd < 0) {
            perror("Failed to open " RANDOM_DEV_FILE);
            exit(1);
        }
    }
    for (size_t i = 0; i < len; i++) {
        do {
            if (read(random_fd, &new_byte, 1) != 1) {
                fprintf(stderr, "Failed to read " RANDOM_DEV_FILE "\n");
                exit(1);
            }
        } while (new_byte == last_byte);

        buf[i] = new_byte;
        last_byte = new_byte;
    }
}

