# Feature Summary

Statistics are computed after loading and cleaning, before the train/test
split. Removal decisions for empty/constant columns are derived from the
TRAINING split only and then applied to both splits (no test-set leakage).

| Feature | Data type | Missing values | Missing ratio | Unique values | Variance | Role | Decision |
|---------|-----------|----------------|---------------|---------------|----------|------|----------|
| Destination_Port | int64 | 0 | 0.00% | 39617 | 3.699e+08 | feature | kept |
| Flow_Duration | int64 | 0 | 0.00% | 336017 | 9.344e+14 | feature | kept |
| Total_Fwd_Packets | int64 | 0 | 0.00% | 970 | 6.663e+05 | feature | kept |
| Total_Backward_Packets | int64 | 0 | 0.00% | 1178 | 1.204e+06 | feature | kept |
| Total_Length_of_Fwd_Packets | int64 | 0 | 0.00% | 11485 | 2.661e+08 | feature | kept |
| Total_Length_of_Bwd_Packets | int64 | 0 | 0.00% | 36353 | 6.189e+12 | feature | kept |
| Fwd_Packet_Length_Max | int64 | 0 | 0.00% | 4191 | 2.281e+05 | feature | kept |
| Fwd_Packet_Length_Min | int64 | 0 | 0.00% | 230 | 1423 | feature | kept |
| Fwd_Packet_Length_Mean | float64 | 0 | 0.00% | 46357 | 1.355e+04 | feature | kept |
| Fwd_Packet_Length_Std | float64 | 0 | 0.00% | 99489 | 2.215e+04 | feature | kept |
| Bwd_Packet_Length_Max | int64 | 0 | 0.00% | 4403 | 7.43e+05 | feature | kept |
| Bwd_Packet_Length_Min | int64 | 0 | 0.00% | 482 | 5231 | feature | kept |
| Bwd_Packet_Length_Mean | float64 | 0 | 0.00% | 68319 | 9.152e+04 | feature | kept |
| Bwd_Packet_Length_Std | float64 | 0 | 0.00% | 101995 | 8.046e+04 | feature | kept |
| Flow_Bytes/s | float64 | 518 | 0.06% | 486981 | 7.176e+14 | feature | kept |
| Flow_Packets/s | float64 | 518 | 0.06% | 370240 | 4.983e+10 | feature | kept |
| Flow_IAT_Mean | float64 | 0 | 0.00% | 360988 | 1.61e+13 | feature | kept |
| Flow_IAT_Std | float64 | 0 | 0.00% | 344959 | 3.24e+13 | feature | kept |
| Flow_IAT_Max | int64 | 0 | 0.00% | 215368 | 1.781e+14 | feature | kept |
| Flow_IAT_Min | int64 | 0 | 0.00% | 72241 | 6.424e+12 | feature | kept |
| Fwd_IAT_Total | int64 | 0 | 0.00% | 159837 | 9.262e+14 | feature | kept |
| Fwd_IAT_Mean | float64 | 0 | 0.00% | 259080 | 8.618e+13 | feature | kept |
| Fwd_IAT_Std | float64 | 0 | 0.00% | 237294 | 1.433e+13 | feature | kept |
| Fwd_IAT_Max | int64 | 0 | 0.00% | 155631 | 1.775e+14 | feature | kept |
| Fwd_IAT_Min | int64 | 0 | 0.00% | 47627 | 8.186e+13 | feature | kept |
| Bwd_IAT_Total | int64 | 0 | 0.00% | 99828 | 8.771e+14 | feature | kept |
| Bwd_IAT_Mean | float64 | 0 | 0.00% | 195522 | 8.703e+13 | feature | kept |
| Bwd_IAT_Std | float64 | 0 | 0.00% | 184744 | 1.194e+13 | feature | kept |
| Bwd_IAT_Max | int64 | 0 | 0.00% | 99102 | 1.611e+14 | feature | kept |
| Bwd_IAT_Min | int64 | 0 | 0.00% | 23365 | 8.252e+13 | feature | kept |
| Fwd_PSH_Flags | int64 | 0 | 0.00% | 2 | 0.04749 | feature | kept |
| Bwd_PSH_Flags | int64 | 0 | 0.00% | 1 | 0 | feature | removed |
| Fwd_URG_Flags | int64 | 0 | 0.00% | 2 | 9.66e-05 | feature | kept |
| Bwd_URG_Flags | int64 | 0 | 0.00% | 1 | 0 | feature | removed |
| Fwd_Header_Length | int64 | 0 | 0.00% | 2487 | 1.507e+15 | feature | kept |
| Bwd_Header_Length | int64 | 0 | 0.00% | 2581 | 6.962e+12 | feature | kept |
| Fwd_Packets/s | float64 | 0 | 0.00% | 365939 | 4.627e+10 | feature | kept |
| Bwd_Packets/s | float64 | 0 | 0.00% | 341377 | 1.473e+09 | feature | kept |
| Min_Packet_Length | int64 | 0 | 0.00% | 168 | 653.2 | feature | kept |
| Max_Packet_Length | int64 | 0 | 0.00% | 5001 | 8.655e+05 | feature | kept |
| Packet_Length_Mean | float64 | 0 | 0.00% | 93858 | 3.474e+04 | feature | kept |
| Packet_Length_Std | float64 | 0 | 0.00% | 142235 | 6.341e+04 | feature | kept |
| Packet_Length_Variance | float64 | 0 | 0.00% | 142229 | 6.13e+10 | feature | kept |
| FIN_Flag_Count | int64 | 0 | 0.00% | 2 | 0.009893 | feature | kept |
| SYN_Flag_Count | int64 | 0 | 0.00% | 2 | 0.04749 | feature | kept |
| RST_Flag_Count | int64 | 0 | 0.00% | 2 | 0.0003428 | feature | kept |
| PSH_Flag_Count | int64 | 0 | 0.00% | 2 | 0.2062 | feature | kept |
| ACK_Flag_Count | int64 | 0 | 0.00% | 2 | 0.1965 | feature | kept |
| URG_Flag_Count | int64 | 0 | 0.00% | 2 | 0.09598 | feature | kept |
| CWE_Flag_Count | int64 | 0 | 0.00% | 2 | 9.66e-05 | feature | kept |
| ECE_Flag_Count | int64 | 0 | 0.00% | 2 | 0.000344 | feature | kept |
| Down/Up_Ratio | int64 | 0 | 0.00% | 25 | 0.3411 | feature | kept |
| Average_Packet_Size | float64 | 0 | 0.00% | 92234 | 3.722e+04 | feature | kept |
| Avg_Fwd_Segment_Size | float64 | 0 | 0.00% | 46357 | 1.355e+04 | feature | kept |
| Avg_Bwd_Segment_Size | float64 | 0 | 0.00% | 68319 | 9.152e+04 | feature | kept |
| Fwd_Header_Length.1 | int64 | 0 | 0.00% | 2487 | 1.507e+15 | feature | kept |
| Fwd_Avg_Bytes/Bulk | int64 | 0 | 0.00% | 1 | 0 | feature | removed |
| Fwd_Avg_Packets/Bulk | int64 | 0 | 0.00% | 1 | 0 | feature | removed |
| Fwd_Avg_Bulk_Rate | int64 | 0 | 0.00% | 1 | 0 | feature | removed |
| Bwd_Avg_Bytes/Bulk | int64 | 0 | 0.00% | 1 | 0 | feature | removed |
| Bwd_Avg_Packets/Bulk | int64 | 0 | 0.00% | 1 | 0 | feature | removed |
| Bwd_Avg_Bulk_Rate | int64 | 0 | 0.00% | 1 | 0 | feature | removed |
| Subflow_Fwd_Packets | int64 | 0 | 0.00% | 970 | 6.663e+05 | feature | kept |
| Subflow_Fwd_Bytes | int64 | 0 | 0.00% | 11485 | 2.652e+08 | feature | kept |
| Subflow_Bwd_Packets | int64 | 0 | 0.00% | 1178 | 1.204e+06 | feature | kept |
| Subflow_Bwd_Bytes | int64 | 0 | 0.00% | 36361 | 6.189e+12 | feature | kept |
| Init_Win_bytes_forward | int64 | 0 | 0.00% | 7938 | 2.139e+08 | feature | kept |
| Init_Win_bytes_backward | int64 | 0 | 0.00% | 8277 | 9.148e+07 | feature | kept |
| act_data_pkt_fwd | int64 | 0 | 0.00% | 601 | 2.399e+05 | feature | kept |
| min_seg_size_forward | int64 | 0 | 0.00% | 19 | 3.829e+12 | feature | kept |
| Active_Mean | float64 | 0 | 0.00% | 120354 | 3.796e+11 | feature | kept |
| Active_Std | float64 | 0 | 0.00% | 79555 | 1.474e+11 | feature | kept |
| Active_Max | int64 | 0 | 0.00% | 115003 | 1.095e+12 | feature | kept |
| Active_Min | int64 | 0 | 0.00% | 70393 | 3.041e+11 | feature | kept |
| Idle_Mean | float64 | 0 | 0.00% | 59295 | 1.589e+14 | feature | kept |
| Idle_Std | float64 | 0 | 0.00% | 77543 | 3.667e+12 | feature | kept |
| Idle_Max | int64 | 0 | 0.00% | 29018 | 1.673e+14 | feature | kept |
| Idle_Min | int64 | 0 | 0.00% | 63550 | 1.545e+14 | feature | kept |
| Label | str | 0 | 0.00% | 7 | - | target | kept |
