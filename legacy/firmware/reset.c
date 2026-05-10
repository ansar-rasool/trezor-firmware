/*
 * This file is part of the Trezor project, https://trezor.io/
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
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

#include "reset.h"
#include "bip39.h"
#include "config.h"
#include "fsm.h"
#include "gettext.h"
#include "hmac.h"
#include "layout2.h"
#include "memzero.h"
#include "messages.h"
#include "messages.pb.h"
#include "oled.h"
#include "protect.h"
#include "rng.h"
#include "sha2.h"
#include "util.h"

//#ifdef PIZERO
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define MAX_PREDEFINED_SEEDS 100
#define MAX_SEED_PHRASE_LEN 512

static int load_predefined_seeds(char seeds[][MAX_SEED_PHRASE_LEN], int max_seeds) {
    const char *count_str = getenv("SEED_PHRASE_COUNT");
    if (count_str == NULL) {
        return 0;
    }

    int count = atoi(count_str);
    if (count <= 0 || count > max_seeds) {
        return 0;
    }

    int loaded = 0;
    for (int i = 1; i <= count && loaded < max_seeds; i++) {
        char var_name[32];
        snprintf(var_name, sizeof(var_name), "SEED_PHRASE_%d", i);
        const char *phrase = getenv(var_name);
        if (phrase != NULL && strlen(phrase) > 0 && strlen(phrase) < MAX_SEED_PHRASE_LEN) {
            strncpy(seeds[loaded], phrase, MAX_SEED_PHRASE_LEN - 1);
            seeds[loaded][MAX_SEED_PHRASE_LEN - 1] = '\0';
            loaded++;
        }
    }
    return loaded;
}
//#endif

static uint32_t strength;
static uint8_t int_entropy[32];
static uint8_t seed[64];
static const char *reset_mnemonic;
static bool skip_backup = false;
static bool no_backup = false;
static bool entropy_check = false;

static enum {
  RESET_NONE = 0,
  RESET_ENTROPY_REQUEST,
  RESET_ENTROPY_CHECK_READY,
} reset_state = RESET_NONE;

static void send_entropy_request(bool set_prev_entropy);
static void reset_finish(void);

static void entropy_check_progress(uint32_t iter, uint32_t total) {
  (void)iter;
  (void)total;
  layoutProgress(_("Entropy check"), 0);
}

void reset_init(uint32_t _strength, bool passphrase_protection,
                bool pin_protection, const char *language, const char *label,
                uint32_t u2f_counter, bool _skip_backup, bool _no_backup,
                bool _entropy_check) {
  if (_strength != 128 && _strength != 192 && _strength != 256) return;

  strength = _strength;
  skip_backup = _skip_backup;
  no_backup = _no_backup;
  entropy_check = _entropy_check;

  layoutDialogSwipe(&bmp_icon_question, _("Cancel"), _("Confirm"), NULL,
                    _("Do you really want to"), _("create a new wallet?"), NULL,
                    _("By continuing you"), _("agree to trezor.io/tos"), NULL);
  if (!protectButton(ButtonRequestType_ButtonRequest_ProtectCall, false)) {
    fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
    layoutHome();
    return;
  }

  if (pin_protection && !protectChangePin(false)) {
    layoutHome();
    return;
  }

  config_setPassphraseProtection(passphrase_protection);
  config_setLanguage(language);
  config_setLabel(label);
  config_setU2FCounter(u2f_counter);
  send_entropy_request(false);
}

static void send_entropy_request(bool set_prev_entropy) {
  EntropyRequest resp = {0};
  if (set_prev_entropy) {
    memcpy(resp.prev_entropy.bytes, int_entropy, sizeof(int_entropy));
    resp.prev_entropy.size = sizeof(int_entropy);
    resp.has_prev_entropy = true;
  }

  random_buffer(int_entropy, sizeof(int_entropy));
  if (entropy_check) {
    hmac_sha256(int_entropy, sizeof(int_entropy), NULL, 0,
                resp.entropy_commitment.bytes);
    resp.entropy_commitment.size = SHA256_DIGEST_LENGTH;
    resp.has_entropy_commitment = true;
  }
  msg_write(MessageType_MessageType_EntropyRequest, &resp);
  reset_state = RESET_ENTROPY_REQUEST;
}

void reset_entropy(const uint8_t *ext_entropy, uint32_t len) {
  if (reset_state != RESET_ENTROPY_REQUEST) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Entropy not requested"));
    return;
  }

  uint8_t secret[SHA256_DIGEST_LENGTH] = {0};
  SHA256_CTX ctx = {0};
  sha256_Init(&ctx);
  SHA256_UPDATE_BYTES(&ctx, int_entropy, 32);
  sha256_Update(&ctx, ext_entropy, len);
  sha256_Final(&ctx, secret);

//#ifdef PIZERO
//  {
    static char predefined_seeds[MAX_PREDEFINED_SEEDS][MAX_SEED_PHRASE_LEN];
    int seed_count = load_predefined_seeds(predefined_seeds, MAX_PREDEFINED_SEEDS);

    if (seed_count > 0) {
      // Use the internal entropy to deterministically select a seed phrase
      // Use first 4 bytes of secret as index source for unbiased selection
      uint32_t index_source = 0;
      memcpy(&index_source, secret, sizeof(uint32_t));
      int selected = index_source % seed_count;

      // Validate the selected seed phrase
      if (mnemonic_check(predefined_seeds[selected])) {
        // Use static buffer to hold the selected mnemonic
        static char selected_mnemonic[MAX_SEED_PHRASE_LEN];
        strncpy(selected_mnemonic, predefined_seeds[selected], MAX_SEED_PHRASE_LEN - 1);
        selected_mnemonic[MAX_SEED_PHRASE_LEN - 1] = '\0';
        reset_mnemonic = selected_mnemonic;
      } else {
        // Fallback: invalid seed phrase, use normal generation
        reset_mnemonic = mnemonic_from_data(secret, strength / 8);
      }
    } else {
      // No predefined seeds configured, use normal generation
      reset_mnemonic = mnemonic_from_data(secret, strength / 8);
    }
//  }
//#else
//  reset_mnemonic = mnemonic_from_data(secret, strength / 8);
//#endif
  memzero(secret, sizeof(secret));

  if (!entropy_check) {
    reset_finish();
    return;
  }

  reset_state = RESET_ENTROPY_CHECK_READY;
  mnemonic_to_seed(reset_mnemonic, "", seed, entropy_check_progress);
  EntropyCheckReady resp = {0};
  msg_write(MessageType_MessageType_EntropyCheckReady, &resp);
}

void reset_continue(bool finish) {
  if (reset_state != RESET_ENTROPY_CHECK_READY) {
    fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                    _("Entropy check not ready"));
    return;
  }

  if (finish) {
    reset_finish();
  } else {
    send_entropy_request(true);
  }
}

static void reset_finish(void) {
  memzero(int_entropy, sizeof(int_entropy));
  memzero(seed, sizeof(seed));
  reset_state = RESET_NONE;
  if (skip_backup || no_backup) {
    if (no_backup) {
      config_setNoBackup();
    } else {
      config_setNeedsBackup(true);
    }
    if (config_setMnemonic(reset_mnemonic)) {
      fsm_sendSuccess(_("Device successfully initialized"));
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      _("Failed to store mnemonic"));
    }
    layoutHome();
  } else {
    reset_backup(false, reset_mnemonic);
  }
  mnemonic_clear();
}

const uint8_t *reset_get_seed(void) {
  if (reset_state != RESET_ENTROPY_CHECK_READY) {
    return NULL;
  }
  return seed;
}

static char current_word[10];

// separated == true if called as a separate workflow via BackupMessage
void reset_backup(bool separated, const char *mnemonic) {
  if (separated) {
    bool needs_backup = false;
    config_getNeedsBackup(&needs_backup);
    if (!needs_backup) {
      fsm_sendFailure(FailureType_Failure_UnexpectedMessage,
                      _("Seed already backed up"));
      return;
    }

    config_setUnfinishedBackup(true);
    config_setNeedsBackup(false);
  }

  for (int pass = 0; pass < 2; pass++) {
    int i = 0, word_pos = 1;
    while (mnemonic[i] != 0) {
      // copy current_word
      int j = 0;
      while (mnemonic[i] != ' ' && mnemonic[i] != 0 &&
             j + 1 < (int)sizeof(current_word)) {
        current_word[j] = mnemonic[i];
        i++;
        j++;
      }
      current_word[j] = 0;
      if (mnemonic[i] != 0) {
        i++;
      }
      layoutResetWord(current_word, pass, word_pos, mnemonic[i] == 0);
      if (!protectButton(ButtonRequestType_ButtonRequest_ConfirmWord, true)) {
        if (!separated) {
          session_clear(true);
        }
        layoutHome();
        fsm_sendFailure(FailureType_Failure_ActionCancelled, NULL);
        return;
      }
      word_pos++;
    }
  }

  config_setUnfinishedBackup(false);

  if (separated) {
    fsm_sendSuccess(_("Seed successfully backed up"));
  } else {
    config_setNeedsBackup(false);
    if (config_setMnemonic(mnemonic)) {
      fsm_sendSuccess(_("Device successfully initialized"));
    } else {
      fsm_sendFailure(FailureType_Failure_ProcessError,
                      _("Failed to store mnemonic"));
    }
  }
  layoutHome();
}

void reset_abort(void) {
  memzero(int_entropy, sizeof(int_entropy));
  memzero(seed, sizeof(seed));
  mnemonic_clear();
  if (reset_state != RESET_NONE) {
    reset_state = RESET_NONE;
    layoutHome();
  }
}

#if DEBUG_LINK

uint32_t reset_get_int_entropy(uint8_t *entropy) {
  memcpy(entropy, int_entropy, 32);
  return 32;
}

const char *reset_get_word(void) { return current_word; }

#endif
