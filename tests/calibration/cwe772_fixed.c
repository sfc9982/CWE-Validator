#include <stdio.h>

FILE *open_patient_records(const char *file_path) {
    return fopen(file_path, "r");
}

int process_patient_records(FILE *records_file) {
    char record_line[128];
    if (records_file == NULL) return 0;
    return fgets(record_line, sizeof(record_line), records_file) != NULL;
}

int func(const char *patient_data_path) {
    FILE *patient_records = open_patient_records(patient_data_path);
    if (patient_records == NULL) {
        perror("Failed to open patient records");
        return 1;
    }
    process_patient_records(patient_records);
    fclose(patient_records);
    return 0;
}

void simulate_long_running_service(const char *file_path, int loop_max) {
    for (int i = 0; i < loop_max; i++) {
        int ret = func(file_path);
        (void)ret;
    }
}

int main(void) {
    const char *patient_data_path = "patient_records.txt";
    simulate_long_running_service(patient_data_path, 20);
    return 0;
}
