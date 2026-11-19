idf_component_register(SRCS "main.c"
                       PRIV_REQUIRES console mbedtls efuse esp_hw_support esp_security nvs_flash
                       INCLUDE_DIRS ".")
