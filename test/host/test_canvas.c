#include "aegis_test.h"
#include "canvas.h"
#include <stdlib.h>

TEST_MAIN_BEGIN
    uint16_t buf[16 * 16];
    canvas_t cv; cv_init(&cv, buf, 16, 16);

    SUITE("canvas: clear + pixel set/read");
    {
        cv_clear(&cv, 0x1234);
        CHECK(buf[0] == 0x1234, "clear fills buffer");
        cv_pixel(&cv, 3, 4, 0xBEEF);
        CHECK(buf[4 * 16 + 3] == 0xBEEF, "pixel writes at x,y");
        CHECK(cv.oob == 0, "in-bounds writes do not count as oob");
    }

    SUITE("canvas: out-of-bounds writes are dropped and counted");
    {
        cv.oob = 0;
        cv_pixel(&cv, -1, 0, 0xFFFF);
        cv_pixel(&cv, 16, 0, 0xFFFF);
        cv_pixel(&cv, 0, 99, 0xFFFF);
        CHECK(cv.oob == 3, "3 oob writes counted, got %u", cv.oob);
    }

    SUITE("canvas: text width + glyph pixels");
    {
        CHECK(cv_text_width("AB", 1) == 12, "2 chars * 6px = 12, got %d", cv_text_width("AB",1));
        CHECK(cv_text_width("AB", 2) == 24, "scale 2 doubles width");
        cv_clear(&cv, 0); cv.oob = 0;
        cv_char(&cv, 0, 0, '!', 0xFFFF, -1, 1);   /* '!' has a top pixel at col2 */
        CHECK(buf[0 * 16 + 2] == 0xFFFF, "'!' sets its top stem pixel");
        CHECK(cv.oob == 0, "drawing a glyph in-bounds is clean");
    }
TEST_MAIN_END
