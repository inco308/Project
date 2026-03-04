/**
 * @file csv_reader.h
 * @brief CSV文件读取模块
 * 
 * 支持多种编码和分隔符的CSV文件读取
 */

#ifndef CSV_READER_H
#define CSV_READER_H

#include "common.h"
#include "csr_graph.h"
#include "dynamic_array.h"

CSRGraph* read_csv_to_graph(const char* file_path);
DynamicArray* read_all_sessions(const char* file_path);

#endif
