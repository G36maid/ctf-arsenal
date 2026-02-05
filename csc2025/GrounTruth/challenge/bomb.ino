// CSC Bomb v1.1.0
// by seadog007

#include <dummy_rp2350.h>

#include <Arduino.h>
#include <U8g2lib.h>
#include <Wire.h>
#include <EEPROM.h>

#define SDA_PIN 4
#define SCL_PIN 5

#define DEBUG 0 // 1 for debug, 0 for production
#define BYPASS_BOOT_CHECK 0 // 1 for bypass, 0 for normal
#define BYPASS_DISCONN_CHECK 0 // 1 for bypass, 0 for normal

U8G2_SSD1306_128X64_NONAME_F_HW_I2C u8g2(U8G2_R0, /* reset=*/ U8X8_PIN_NONE, /* clock=*/ SCL_PIN, /* data=*/ SDA_PIN);

unsigned long totalSeconds = 15 * 60; // 15 minutes = 900 seconds
unsigned long previousMillis = 0;
const unsigned long interval = 1000; // 1 second

char secret[EEPROM_SECRET_LENGTH + 1] = {0}; // initialize to 0
const int check_pins[] = {8,9,10,11,12,13,14,15,0,22,21,20,19,18,17,16};
const int num_pins = sizeof(check_pins) / sizeof(check_pins[0]);
int pins_order[num_pins];

uint8_t seed = 0;
char seedString[EEPROM_SEED_LENGTH * 2 + 1];

// SHA512 implementation (self-contained)
#define SHA512_BLOCK_SIZE 128
#define SHA512_DIGEST_SIZE 64

static const uint64_t sha512_k[80] = {
    0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
    0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
    0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
    0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
    0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
    0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
    0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
    0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
    0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
    0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
    0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
    0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
    0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
    0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
    0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
    0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
    0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
    0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
    0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
    0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 28) ^ ROTR(x, 34) ^ ROTR(x, 39))
#define EP1(x) (ROTR(x, 14) ^ ROTR(x, 18) ^ ROTR(x, 41))
#define SIG0(x) (ROTR(x, 1) ^ ROTR(x, 8) ^ ((x) >> 7))
#define SIG1(x) (ROTR(x, 19) ^ ROTR(x, 61) ^ ((x) >> 6))

void sha512_transform(uint64_t state[8], const uint8_t data[SHA512_BLOCK_SIZE]) {
    uint64_t a, b, c, d, e, f, g, h, t1, t2, m[80];
    size_t i, j;
    
    for (i = 0, j = 0; i < 16; ++i, j += 8) {
        m[i] = ((uint64_t)data[j] << 56) | ((uint64_t)data[j + 1] << 48) |
               ((uint64_t)data[j + 2] << 40) | ((uint64_t)data[j + 3] << 32) |
               ((uint64_t)data[j + 4] << 24) | ((uint64_t)data[j + 5] << 16) |
               ((uint64_t)data[j + 6] << 8) | ((uint64_t)data[j + 7]);
    }
    for (; i < 80; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }
    
    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];
    
    for (i = 0; i < 80; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + sha512_k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }
    
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha512(const uint8_t *data, size_t length, uint8_t *hash) {
    uint64_t state[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
        0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL, 0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
    };
    
    uint8_t msg_block[SHA512_BLOCK_SIZE];
    size_t block_offset = 0;
    uint64_t bit_len = (uint64_t)length * 8;
    size_t i;
    
    // Process full blocks
    while (length >= SHA512_BLOCK_SIZE) {
        for (i = 0; i < SHA512_BLOCK_SIZE; i++) {
            msg_block[i] = data[block_offset + i];
        }
        sha512_transform(state, msg_block);
        block_offset += SHA512_BLOCK_SIZE;
        length -= SHA512_BLOCK_SIZE;
    }
    
    // Process remaining bytes
    for (i = 0; i < length; i++) {
        msg_block[i] = data[block_offset + i];
    }
    
    // Padding
    msg_block[length] = 0x80;
    for (i = length + 1; i < SHA512_BLOCK_SIZE; i++) {
        msg_block[i] = 0;
    }
    
    // Add length in bits (big-endian) to the last 16 bytes
    if (length >= 112) {
        sha512_transform(state, msg_block);
        for (i = 0; i < SHA512_BLOCK_SIZE; i++) {
            msg_block[i] = 0;
        }
    }
    
    // Write bit length as 128-bit big-endian (upper 64 bits are 0 for our use case)
    for (i = 112; i < 120; i++) {
        msg_block[i] = 0;
    }
    msg_block[120] = (bit_len >> 56) & 0xff;
    msg_block[121] = (bit_len >> 48) & 0xff;
    msg_block[122] = (bit_len >> 40) & 0xff;
    msg_block[123] = (bit_len >> 32) & 0xff;
    msg_block[124] = (bit_len >> 24) & 0xff;
    msg_block[125] = (bit_len >> 16) & 0xff;
    msg_block[126] = (bit_len >> 8) & 0xff;
    msg_block[127] = bit_len & 0xff;
    sha512_transform(state, msg_block);
    
    // Output hash as big-endian
    for (i = 0; i < 8; i++) {
        hash[i * 8] = (state[i] >> 56) & 0xff;
        hash[i * 8 + 1] = (state[i] >> 48) & 0xff;
        hash[i * 8 + 2] = (state[i] >> 40) & 0xff;
        hash[i * 8 + 3] = (state[i] >> 32) & 0xff;
        hash[i * 8 + 4] = (state[i] >> 24) & 0xff;
        hash[i * 8 + 5] = (state[i] >> 16) & 0xff;
        hash[i * 8 + 6] = (state[i] >> 8) & 0xff;
        hash[i * 8 + 7] = state[i] & 0xff;
    }
}

  void calculate_pins_order(const char *seedString, int pins_order[num_pins]) {
  // calculate sha512(sha512(seedString))) for key string
  uint8_t hash[64];
  sha512((uint8_t *)seedString, EEPROM_SEED_LENGTH * 2, hash);
  sha512((uint8_t *)hash, 64, hash);

  // accumulate bit in hash[i] in pins_order
  // 1 bit in hash[0] will goes to accumulator of pins_order[0]
  // 2 bit in hash[0] will goes to accumulator of pins_order[1]
  // 3 bit in hash[0] will goes to accumulator of pins_order[2]
  // ...
  // 8 bit in hash[0] will goes to accumulator of pins_order[7]
  // 1 bit in hash[1] will goes to accumulator of pins_order[8]
  // 2 bit in hash[1] will goes to accumulator of pins_order[9]
  // ...
  // 8 bit in hash[1] will goes to accumulator of pins_order[15]
  // 1 bit in hash[2] will goes to accumulator of pins_order[0]
  // 2 bit in hash[2] will goes to accumulator of pins_order[1]
  
  // Initialize pins_order to 0
  for (int i = 0; i < num_pins; i++) {
    pins_order[i] = 0;
  }
  
  // Distribute bits from hash to pins_order
  // For each byte in hash (i = 0 to 63)
  // For each bit position in that byte (j = 0 to 7, where j=0 is LSB/bit 1, j=7 is MSB/bit 8)
  // Add the bit value to pins_order[(i * 8 + j) % num_pins]
  for (int i = 0; i < 64; i++) {
    for (int j = 0; j < 8; j++) {
      int pin_idx = (i * 8 + j) % num_pins;
      if (hash[i] & (1 << j)) {
        pins_order[pin_idx]++;
      }
    }
  }

  // reformat pins_order 
  // [23, 52, 24, 1] -> [2, 4, 3, 1]
  // [24, 24, 23, 23] -> [3, 4, 1, 2]
  // [24, 24, 24, 24] -> [1, 2, 3, 4]
  // Convert values to ranks: smallest value = rank 1, next smallest = rank 2, etc.
  // If values are equal, the first occurrence gets the lower rank
  
  // Create array of pairs: (value, original_index)
  struct {
    int value;
    int original_index;
  } pairs[num_pins];
  
  for (int i = 0; i < num_pins; i++) {
    pairs[i].value = pins_order[i];
    pairs[i].original_index = i;
  }
  
  // Sort pairs by value, then by original_index (first occurrence gets priority)
  for (int i = 0; i < num_pins - 1; i++) {
    for (int j = 0; j < num_pins - i - 1; j++) {
      if (pairs[j].value > pairs[j + 1].value || 
          (pairs[j].value == pairs[j + 1].value && pairs[j].original_index > pairs[j + 1].original_index)) {
        // Swap
        int temp_val = pairs[j].value;
        int temp_idx = pairs[j].original_index;
        pairs[j].value = pairs[j + 1].value;
        pairs[j].original_index = pairs[j + 1].original_index;
        pairs[j + 1].value = temp_val;
        pairs[j + 1].original_index = temp_idx;
      }
    }
  }
  
  // Assign ranks (1, 2, 3, ...) to sorted pairs
  int ranks[num_pins];
  for (int i = 0; i < num_pins; i++) {
    ranks[pairs[i].original_index] = i + 1;
  }
  
  // Copy ranks back to pins_order
  for (int i = 0; i < num_pins; i++) {
    pins_order[i] = ranks[i];
  }
}

void setup(void) {
  u8g2.begin();
  u8g2.enableUTF8Print();
  u8g2.setFont(u8g2_font_t0_16b_mf);

  // Initialize EEPROM first to check timeout flag
  EEPROM.begin(EEPROM_SIZE);
  
  // Check if timeout flag is set - if so, don't boot
  uint8_t detonatedFlag = EEPROM.read(EEPROM_DETONATED_FLAG_ADDR);
  uint8_t bootedFlag = EEPROM.read(EEPROM_BOOTED_FLAG_ADDR);
  if (detonatedFlag || bootedFlag) {
    // Prevent booting up
    u8g2.clearBuffer();
    u8g2.setCursor(5, 10);
    u8g2.print("Your bomb is");
    u8g2.setCursor(5, 25);
    u8g2.print("already");
    u8g2.setCursor(5, 40);
    u8g2.print("detonated!");
    u8g2.setCursor(5, 60);
    u8g2.print("System locked!");
#if DEBUG
    u8g2.setCursor(100, 25);
    u8g2.print(detonatedFlag);
    u8g2.setCursor(100, 40);
    u8g2.print(bootedFlag);
#endif
    u8g2.sendBuffer();
    delay(2000);

#if !BYPASS_BOOT_CHECK
    // Halt execution - don't boot up
    while (true) {
      delay(1000);
    }
#endif
  }

  for (int i = 0; i < num_pins; i++) {
    pinMode(check_pins[i], INPUT); // use INPUT or INPUT_PULLUP as needed
  }

#if !BYPASS_DISCONN_CHECK
  // Do a precheck of all pins
  for (int i = 0; i < num_pins; i++) {
    int state = digitalRead(check_pins[i]);
    if (state == HIGH) {
      u8g2.clearBuffer();
      u8g2.setCursor(10, 30);
      u8g2.print("Pin ");
      u8g2.print(i);
      u8g2.print(" discon");
      u8g2.sendBuffer();
    }
    while (state == HIGH) {
      state = digitalRead(check_pins[i]);
    }
  }
#endif
  // Wait 5 second before actually boot
  u8g2.clearBuffer();
  u8g2.setCursor(30, 40);
  u8g2.print("Booting...");
  u8g2.sendBuffer();
  delay(5000);

  EEPROM.write(EEPROM_BOOTED_FLAG_ADDR, 1);
  EEPROM.commit();

  // Read seed from EEPROM
  for (int i = 0; i < EEPROM_SEED_LENGTH; i++) {
    seed = EEPROM.read(EEPROM_SEED_ADDR + i);
    sprintf(seedString + i * 2, "%02x", seed);
  }

  calculate_pins_order(seedString, pins_order);

  // Read encryptedSecret from EEPROM
  char encryptedSecret[EEPROM_SECRET_LENGTH + 1];
  for (int i = 0; i <= EEPROM_SECRET_LENGTH; i++) {
    encryptedSecret[i] = EEPROM.read(EEPROM_SECRET_ADDR + i);
    EEPROM.write(EEPROM_SECRET_ADDR + i, 0);
  }
  EEPROM.commit();
  // decrypt encryptedSecret with pins_order
  for (int i = 0; i <= EEPROM_SECRET_LENGTH; i++) {
    secret[i] = encryptedSecret[i] ^ pins_order[i % num_pins];
  }
}
int i = 50;
char timeString[6];

void updateTimeString() {
  int minutes = totalSeconds / 60;
  int seconds = totalSeconds % 60;

  // Format into mm:ss with leading zeros
  sprintf(timeString, "%02d:%02d", minutes, seconds);
}

String pinStatesRow1 = "";
String pinStatesRow2 = "";
const int pinsPerRow = 8; // Display  pins per row

void updatePinState() {
  pinStatesRow1 = "";
  pinStatesRow2 = "";
  // Read each pin and append 'o' or 'x', split into rows
  for (int i = 0; i < num_pins; i++) {
    int state = digitalRead(check_pins[i]);
    char stateChar = (state == HIGH) ? 'x' : 'o';
    
    if (i < pinsPerRow) {
      pinStatesRow1 += stateChar;
    } else {
      pinStatesRow2 += stateChar;
    }
  }
}

void detonate() {
  // Set timeout flag only
  EEPROM.write(EEPROM_DETONATED_FLAG_ADDR, 1); // 1 means detonated
  
  // Commit to flash (actually write the data)
  EEPROM.commit();
}

void win() {
  // print secret
  u8g2.clearBuffer();
  u8g2.setCursor(35, 15);
  u8g2.print("You win!");
  u8g2.setCursor(30, 35);
  // first half of secret
  for (int i = 0; i < EEPROM_SECRET_LENGTH / 2; i++) {
    u8g2.print(secret[i]);
  }
  u8g2.setCursor(30, 50);
  // second half of secret
  for (int i = EEPROM_SECRET_LENGTH / 2; i < EEPROM_SECRET_LENGTH; i++) {
    u8g2.print(secret[i]);
  }
  u8g2.sendBuffer();
  while (true) {
    delay(1000);
  }
}

void check_disconn() {
  // Find which pins is disconnected after last check_pins(),
  // if there is any, check corresponding pins in pins_order
  // if it is 1, then deduce all values in pins_order by 1, if it is not 1, call detonate()
  
  static int prev_pin_states[num_pins] = {LOW};
  
  // Read current pin states and find newly disconnected pins
  bool found_disconnected = false;
  bool should_decrement = true;
  
  for (int i = 0; i < num_pins; i++) {
    int current_state = digitalRead(check_pins[i]);
    
    // Check if pin changed from LOW (connected) to HIGH (disconnected)
    if (prev_pin_states[i] == LOW && current_state == HIGH) {
      found_disconnected = true;
      
      // Check corresponding value in pins_order
      if (pins_order[i] == 1) {
        // This pin is correct, will decrement all values
      } else {
        // Wrong pin disconnected - must detonate
        should_decrement = false;
      }
    }
    
    // Update previous state
    prev_pin_states[i] = current_state;
  }
  
  // Process disconnections
  if (found_disconnected) {
    if (should_decrement) {
      // All disconnected pins had value 1, decrement all pins_order values by 1
      for (int i = 0; i < num_pins; i++) {
        if (pins_order[i] > 0) {
          pins_order[i]--;
        }
      }
      // If all value in pins_order is 0, then call win()
      bool winFlag = true;
      for (int i = 0; i < num_pins; i++) {
        if (pins_order[i] != 0) {
          winFlag = false;
        }
      }
      if (winFlag) {
        win();
      }
    } else {
      // At least one disconnected pin had value != 1, detonate!
      detonate();
      u8g2.clearBuffer();
      u8g2.setCursor(25, 30);
      u8g2.print("Wrong Wire!");
      u8g2.setCursor(30, 50);
      u8g2.print("Kaboomed!");
      u8g2.sendBuffer();
      delay(2000);
      
      u8g2.clearBuffer();
      u8g2.setCursor(15, 40);
      u8g2.print("Resetting...");
      u8g2.sendBuffer();

      delay(2000);
      rp2040.restart();
    }
  }
}

void loop(void) {
  unsigned long currentMillis = millis();

  if (currentMillis - previousMillis >= interval) {
    previousMillis = currentMillis;

    if (totalSeconds > 0) {
      check_disconn();
      totalSeconds--;
      updateTimeString();
      u8g2.clearBuffer();
      u8g2.drawUTF8(1, 15, "Time Left:");
      u8g2.setCursor(85, 15);
      u8g2.print(timeString);
      u8g2.drawUTF8(1, 30, "S/N:");
      u8g2.setCursor(40, 30);
      u8g2.print(seedString);
      updatePinState();
      u8g2.setCursor(30, 45);
      u8g2.print(pinStatesRow1);
      u8g2.setCursor(30, 60);
      u8g2.print(pinStatesRow2);
      u8g2.sendBuffer();
    } else {
      detonate();
      u8g2.clearBuffer();
      u8g2.setCursor(25, 30);
      u8g2.print("Time's up!");
      u8g2.setCursor(30, 50);
      u8g2.print("Kaboomed!");
      u8g2.sendBuffer();

      delay(2000);
      
      u8g2.clearBuffer();
      u8g2.setCursor(15, 40);
      u8g2.print("Resetting...");
      u8g2.sendBuffer();

      delay(2000);
      rp2040.restart();
    }
  }
}
