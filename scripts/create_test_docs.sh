#!/bin/bash
# Create test documents of varying sizes in SQLite database

DB_PATH="data/documents.db"

echo "Creating test documents of varying sizes..."
echo "=============================================="

# Function to generate content of specific size
generate_content() {
  size=$1
  # Generate HTML content of specified size
  header="<html><body><h1>Test Document</h1><p>"
  footer="</p></body></html>"
  header_size=${#header}
  footer_size=${#footer}
  content_size=$((size - header_size - footer_size))

  if [ $content_size -lt 0 ]; then
    content_size=10
  fi

  # Generate content using base64 for variety
  content=$(head -c $content_size /dev/urandom | base64 | tr -d '\n' | head -c $content_size)
  echo "${header}${content}${footer}"
}

# Create documents: 1KB, 10KB, 100KB, 1MB
sizes=(1024 10240 102400 1048576)
names=("doc_1kb" "doc_10kb" "doc_100kb" "doc_1mb")

for i in "${!sizes[@]}"; do
  size=${sizes[$i]}
  name=${names[$i]}

  echo "Creating $name (${size} bytes)..."

  content=$(generate_content $size)
  actual_size=${#content}

  # Insert into database
  sqlite3 $DB_PATH <<EOF
INSERT OR REPLACE INTO documents (id, mime, content)
VALUES ('$name', 'text/html', '$content');
EOF

  echo "  Created: $name (actual size: $actual_size bytes)"
done

echo ""
echo "Verifying documents in database..."
sqlite3 $DB_PATH "SELECT id, mime, length(content) as size FROM documents WHERE id LIKE 'doc_%' ORDER BY length(content);"

echo ""
echo "Test documents created successfully!"
