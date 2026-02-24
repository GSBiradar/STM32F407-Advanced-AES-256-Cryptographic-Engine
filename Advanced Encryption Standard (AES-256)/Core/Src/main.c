/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Interactive AES256-CBC with user input
  ******************************************************************************
  */
/* USER CODE END Header */

/* Includes ------------------------------------------------------------------*/
#include "main.h"
#include "stdio.h"
#include "string.h"
#include "stdlib.h"

/* USER CODE BEGIN Includes */
#include "aes256_soft.h"
/* USER CODE END Includes */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */
static uint8_t key[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
    0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
};

static uint8_t iv[16] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
};

#define MAX_INPUT_SIZE 256
#define BLOCK_SIZE 16

static uint8_t input_buffer[MAX_INPUT_SIZE];
static uint8_t ciphertext[MAX_INPUT_SIZE];
static uint8_t padded_input[MAX_INPUT_SIZE];
static AES256_CTX aes_ctx;

// For printf redirection
int _write(int file, char *ptr, int len) {
    HAL_UART_Transmit(&huart2, (uint8_t*)ptr, len, HAL_MAX_DELAY);
    return len;
}
/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);

/* USER CODE BEGIN 0 */
void print_hex(const char* label, uint8_t* data, uint32_t len) {
    printf("%s (%d bytes):\r\n", label, len);
    for(uint32_t i = 0; i < len; i++) {
        printf("%02X ", data[i]);
        if((i + 1) % 16 == 0) printf("\r\n");
    }
    printf("\r\n");
}

// PKCS#7 Padding
uint32_t pkcs7_pad(uint8_t *input, uint32_t input_len, uint8_t *output, uint32_t output_max) {
    uint32_t block_count = (input_len / BLOCK_SIZE) + 1;
    uint32_t padded_len = block_count * BLOCK_SIZE;
    uint8_t pad_value = BLOCK_SIZE - (input_len % BLOCK_SIZE);

    if(padded_len > output_max) {
        return 0; // Output buffer too small
    }

    // Copy input
    memcpy(output, input, input_len);

    // Add padding
    for(uint32_t i = input_len; i < padded_len; i++) {
        output[i] = pad_value;
    }

    return padded_len;
}

// Receive user input via UART
uint32_t receive_user_input(uint8_t *buffer, uint32_t max_size) {
    uint32_t index = 0;
    uint8_t c;

    printf("\r\nEnter your message (press Enter when done):\r\n> ");

    while(index < max_size - 1) {
        // Wait for character
        while(HAL_UART_Receive(&huart2, &c, 1, HAL_MAX_DELAY) != HAL_OK);

        // Echo character
        HAL_UART_Transmit(&huart2, &c, 1, HAL_MAX_DELAY);

        if(c == '\r' || c == '\n') {
            printf("\r\n"); // New line
            break;
        }

        buffer[index++] = c;
    }

    buffer[index] = '\0'; // Null terminate
    return index;
}

// Display menu
void show_menu(void) {
    printf("\r\n");
    printf("========================================\r\n");
    printf("STM32F407 AES256-CBC Interactive Tool\r\n");
    printf("========================================\r\n");
    printf("1. Enter text to encrypt\r\n");
    printf("2. Encrypt with current key/IV\r\n");
    printf("3. Change encryption key\r\n");
    printf("4. Change IV\r\n");
    printf("5. Show current key and IV\r\n");
    printf("6. Exit\r\n");
    printf("========================================\r\n");
    printf("Choice: ");
}

// Parse hex input
uint32_t parse_hex_input(uint8_t *buffer, uint32_t max_len) {
    uint32_t index = 0;
    uint8_t c;
    uint8_t hex_byte = 0;
    int nibble_count = 0;

    printf("Enter hex bytes (e.g., 00112233...), press Enter when done:\r\n> ");

    while(index < max_len) {
        while(HAL_UART_Receive(&huart2, &c, 1, HAL_MAX_DELAY) != HAL_OK);
        HAL_UART_Transmit(&huart2, &c, 1, HAL_MAX_DELAY);

        if(c == '\r' || c == '\n') {
            printf("\r\n");
            break;
        }

        // Convert hex character to nibble
        uint8_t nibble;
        if(c >= '0' && c <= '9') nibble = c - '0';
        else if(c >= 'A' && c <= 'F') nibble = c - 'A' + 10;
        else if(c >= 'a' && c <= 'f') nibble = c - 'a' + 10;
        else continue; // Skip invalid characters

        if(nibble_count == 0) {
            hex_byte = nibble << 4;
            nibble_count = 1;
        } else {
            hex_byte |= nibble;
            buffer[index++] = hex_byte;
            nibble_count = 0;
        }
    }

    return index;
}

// Interactive encryption function
void interactive_encrypt(void) {
    uint32_t input_len;
    uint32_t padded_len;

    // Get user input
    input_len = receive_user_input(input_buffer, MAX_INPUT_SIZE);

    if(input_len == 0) {
        printf("No input received!\r\n");
        return;
    }

    printf("\r\nInput received: \"%s\" (%d bytes)\r\n", input_buffer, input_len);

    // Pad the input to multiple of 16 bytes
    padded_len = pkcs7_pad(input_buffer, input_len, padded_input, MAX_INPUT_SIZE);

    if(padded_len == 0) {
        printf("Error: Input too long or padding failed!\r\n");
        return;
    }

    printf("After padding: %d bytes\r\n", padded_len);
    print_hex("Padded input", padded_input, padded_len);

    // Encrypt
    printf("Encrypting...\r\n");
    AES256_CBC_Encrypt(&aes_ctx, ciphertext, padded_input, padded_len, iv);

    // Show results
    printf("\r\n✓ ENCRYPTION COMPLETE\r\n");
    printf("========================================\r\n");
    printf("CIPHERTEXT:\r\n");
    print_hex("Ciphertext", ciphertext, padded_len);

    // Also show as continuous hex string for easy copying
    printf("Ciphertext as hex string:\r\n");
    for(uint32_t i = 0; i < padded_len; i++) {
        printf("%02X", ciphertext[i]);
    }
    printf("\r\n");
    printf("========================================\r\n");

    // Option to decrypt back for verification
    printf("\r\nDecrypt to verify? (y/n): ");

    uint8_t response;
    while(HAL_UART_Receive(&huart2, &response, 1, HAL_MAX_DELAY) != HAL_OK);
    HAL_UART_Transmit(&huart2, &response, 1, HAL_MAX_DELAY);
    printf("\r\n");

    if(response == 'y' || response == 'Y') {
        uint8_t decrypted[MAX_INPUT_SIZE];
        AES256_CBC_Decrypt(&aes_ctx, decrypted, ciphertext, padded_len, iv);

        // Remove padding
        uint8_t pad_value = decrypted[padded_len - 1];
        uint32_t original_len = padded_len - pad_value;
        decrypted[original_len] = '\0';

        printf("Decrypted text: \"%s\"\r\n", decrypted);
        print_hex("Decrypted hex", decrypted, original_len);

        if(memcmp(input_buffer, decrypted, input_len) == 0) {
            printf("✓ Verification successful!\r\n");
        } else {
            printf("✗ Verification failed!\r\n");
        }
    }
}

// Change key
void change_key(void) {
    uint8_t new_key[32];
    uint32_t key_len;

    printf("\r\nEnter new 32-byte (256-bit) key in hex:\r\n");
    key_len = parse_hex_input(new_key, 32);

    if(key_len != 32) {
        printf("Error: Key must be exactly 32 bytes! Received %d bytes\r\n", key_len);
        return;
    }

    memcpy(key, new_key, 32);
    AES256_KeyExpansion(&aes_ctx, key);
    printf("✓ Key updated successfully!\r\n");
}

// Change IV
void change_iv(void) {
    uint8_t new_iv[16];
    uint32_t iv_len;

    printf("\r\nEnter new 16-byte IV in hex:\r\n");
    iv_len = parse_hex_input(new_iv, 16);

    if(iv_len != 16) {
        printf("Error: IV must be exactly 16 bytes! Received %d bytes\r\n", iv_len);
        return;
    }

    memcpy(iv, new_iv, 16);
    printf("✓ IV updated successfully!\r\n");
}

// Show current key and IV
void show_key_iv(void) {
    printf("\r\nCurrent Key (32 bytes):\r\n");
    for(int i = 0; i < 32; i++) {
        printf("%02X", key[i]);
        if((i + 1) % 8 == 0) printf(" ");
        if((i + 1) % 16 == 0) printf("\r\n");
    }
    printf("\r\n");

    printf("Current IV (16 bytes):\r\n");
    for(int i = 0; i < 16; i++) {
        printf("%02X", iv[i]);
        if((i + 1) % 8 == 0) printf(" ");
    }
    printf("\r\n\r\n");
}
/* USER CODE END 0 */

int main(void) {
    /* MCU Configuration--------------------------------------------------------*/
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USART2_UART_Init();

    /* USER CODE BEGIN 2 */
    printf("\r\n\r\n");
    printf("╔════════════════════════════════════════╗\r\n");
    printf("║   STM32F407 AES256-CBC Interactive    ║\r\n");
    printf("║        Enter text → Get Ciphertext    ║\r\n");
    printf("╚════════════════════════════════════════╝\r\n\r\n");

    // Initialize AES context
    AES256_KeyExpansion(&aes_ctx, key);
    printf("✓ AES256 initialized with default key/IV\r\n");

    int choice;
    char choice_str[2];

    while(1) {
        show_menu();

        // Get user choice
        while(HAL_UART_Receive(&huart2, (uint8_t*)choice_str, 1, HAL_MAX_DELAY) != HAL_OK);
        HAL_UART_Transmit(&huart2, (uint8_t*)choice_str, 1, HAL_MAX_DELAY);
        choice = choice_str[0] - '0';

        printf("\r\n\r\n");

        switch(choice) {
            case 1:
                interactive_encrypt();
                break;

            case 2:
                printf("Using current key/IV for encryption\r\n");
                // Quick encrypt with sample text
                {
                    uint8_t sample[] = "Quick test message";
                    uint32_t padded_len;

                    padded_len = pkcs7_pad(sample, strlen((char*)sample), padded_input, MAX_INPUT_SIZE);
                    AES256_CBC_Encrypt(&aes_ctx, ciphertext, padded_input, padded_len, iv);

                    printf("Sample text: \"%s\"\r\n", sample);
                    printf("Ciphertext: ");
                    for(uint32_t i = 0; i < padded_len; i++) {
                        printf("%02X", ciphertext[i]);
                    }
                    printf("\r\n");
                }
                break;

            case 3:
                change_key();
                break;

            case 4:
                change_iv();
                break;

            case 5:
                show_key_iv();
                break;

            case 6:
                printf("Exiting... Goodbye!\r\n");
                while(1) {
                    HAL_GPIO_TogglePin(LD4_GPIO_Port, LD4_Pin);
                    HAL_Delay(200);
                }
                break;

            default:
                printf("Invalid choice! Please select 1-6.\r\n");
                break;
        }

        printf("\r\nPress any key to continue...\r\n");
        uint8_t dummy;
        HAL_UART_Receive(&huart2, &dummy, 1, HAL_MAX_DELAY);
    }
    /* USER CODE END 2 */
}

/**
  * @brief System Clock Configuration
  */
void SystemClock_Config(void) {
    RCC_OscInitTypeDef RCC_OscInitStruct = {0};
    RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

    __HAL_RCC_PWR_CLK_ENABLE();
    __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE1);

    RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
    RCC_OscInitStruct.HSEState = RCC_HSE_ON;
    RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
    RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
    RCC_OscInitStruct.PLL.PLLM = 8;
    RCC_OscInitStruct.PLL.PLLN = 336;
    RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
    RCC_OscInitStruct.PLL.PLLQ = 7;
    HAL_RCC_OscConfig(&RCC_OscInitStruct);

    RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK | RCC_CLOCKTYPE_SYSCLK
                                | RCC_CLOCKTYPE_PCLK1 | RCC_CLOCKTYPE_PCLK2;
    RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
    RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
    RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV4;
    RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV2;
    HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_5);
}

/**
  * @brief USART2 Initialization Function
  */
static void MX_USART2_UART_Init(void) {
    huart2.Instance = USART2;
    huart2.Init.BaudRate = 115200;
    huart2.Init.WordLength = UART_WORDLENGTH_8B;
    huart2.Init.StopBits = UART_STOPBITS_1;
    huart2.Init.Parity = UART_PARITY_NONE;
    huart2.Init.Mode = UART_MODE_TX_RX;
    huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
    huart2.Init.OverSampling = UART_OVERSAMPLING_16;
    HAL_UART_Init(&huart2);
}

/**
  * @brief GPIO Initialization Function
  */
static void MX_GPIO_Init(void) {
    GPIO_InitTypeDef GPIO_InitStruct = {0};

    __HAL_RCC_GPIOD_CLK_ENABLE();
    __HAL_RCC_GPIOA_CLK_ENABLE();

    GPIO_InitStruct.Pin = LD4_Pin | LD3_Pin | LD5_Pin | LD6_Pin;
    GPIO_InitStruct.Mode = GPIO_MODE_OUTPUT_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_LOW;
    HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

    GPIO_InitStruct.Pin = GPIO_PIN_2 | GPIO_PIN_3;
    GPIO_InitStruct.Mode = GPIO_MODE_AF_PP;
    GPIO_InitStruct.Pull = GPIO_NOPULL;
    GPIO_InitStruct.Speed = GPIO_SPEED_FREQ_VERY_HIGH;
    GPIO_InitStruct.Alternate = GPIO_AF7_USART2;
    HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);
}
