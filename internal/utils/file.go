package utils

import (
	"bufio"
	"fmt"
	"os"
)

func FileExists(filename string) bool {
	info, err := os.Stat(filename)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir()
}

func WriteLinesToFile(lines []string, filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return fmt.Errorf("error al crear archivo %s: %w", filename, err)
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range lines {
		_, err := writer.WriteString(line + "\n")
		if err != nil {
			return fmt.Errorf("error al escribir en archivo %s: %w", filename, err)
		}
	}

	return writer.Flush()
}

func ReadLinesFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("error al abrir archivo %s: %w", filename, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error al leer archivo %s: %w", filename, err)
	}

	return lines, nil
}
