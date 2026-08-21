# Pure-C UI layer (canvas + dashboard composition + font). Host-testable; on
# device it depends only on the engine component for the finding/verdict types.
idf_component_register(
    SRCS "src/canvas.c"
         "src/ui.c"
         "src/font5x8.c"
    INCLUDE_DIRS "include"
    REQUIRES engine
)
