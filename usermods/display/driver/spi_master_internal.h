// Copyright 2010-2017 Espressif Systems (Shanghai) PTE LTD
// Copyright (c) 2018 LoBo (https://github.com/loboris)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.


#ifndef _DRIVER_SPI_MASTER_INTERNAL_H_
#define _DRIVER_SPI_MASTER_INTERNAL_H_

#include "soc/spi_struct.h"
#include "driver/spi_master.h"
#include "esp_pm.h"

#ifdef __cplusplus
extern "C"
{
#endif

typedef struct spi_device_t spi_device_t;
typedef typeof(SPI1.clock) spi_clock_reg_t;

#define NO_CS 6     //Number of CS pins per SPI host including software handled
#define NO_HWCS 3   //Number of hardware handled CS pins per SPI host

#ifdef CONFIG_SPI_MASTER_ISR_IN_IRAM
#define SPI_MASTER_ISR_ATTR IRAM_ATTR
#else
#define SPI_MASTER_ISR_ATTR
#endif

#ifdef CONFIG_SPI_MASTER_IN_IRAM
#define SPI_MASTER_ATTR IRAM_ATTR
#else
#define SPI_MASTER_ATTR
#endif

/// struct to hold private transaction data (like tx and rx buffer for DMA).
typedef struct {
    spi_transaction_t   *trans;
    uint32_t *buffer_to_send;   //equals to tx_data, if SPI_TRANS_USE_RXDATA is applied; otherwise if original buffer wasn't in DMA-capable memory, this gets the address of a temporary buffer that is;
                                //otherwise sets to the original buffer or NULL if no buffer is assigned.
    uint32_t *buffer_to_rcv;    // similar to buffer_to_send
} spi_trans_priv;

typedef struct {
    spi_device_t *device[NO_CS];
    intr_handle_t intr;
    spi_dev_t *hw;
    spi_trans_priv cur_trans_buf;
    int cur_cs;
    int prev_cs;
    lldesc_t *dmadesc_tx;
    lldesc_t *dmadesc_rx;
    uint32_t flags;
    int dma_chan;
    int max_transfer_sz;
    spi_bus_config_t bus_cfg;
#ifdef CONFIG_PM_ENABLE
    esp_pm_lock_handle_t pm_lock;
#endif
} spi_host_t;

typedef struct {
    spi_clock_reg_t reg;
    int eff_clk;
    int dummy_num;
    int miso_delay;
} clock_config_t;

struct spi_device_t {
    QueueHandle_t trans_queue;
    QueueHandle_t ret_queue;
    spi_device_interface_config_t cfg;
    clock_config_t clk_cfg;
    spi_host_t *host;
};

#ifdef __cplusplus
}
#endif

#endif
