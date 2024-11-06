#print ENV variables
echo "Running Test Harness ...\n"

for var in $(env); do
    # Extract the variable name
    name="${var%%=*}"

    # Check if the variable name matches the pattern
    if [[ "$name" == *"SNYK_"* ]]; then
        # Print the variable name and value
        echo "$var"
    fi
done

if [ "$1" = "--debug" ]; then
    echo "Verbose mode enabled"
fi

echo "\n"

for file in test_files/positive/standard/*.json; do
    if [ -f "$file" ]; then
        export SBOM_FILE="$file"
        echo "Testing standard SBOM FILE $SBOM_FILE"
        if [ "$1" = "--debug" ]; then
            poetry run python3 main.py --debug monitor
        else
            poetry run python3 main.py monitor
        fi
    fi
done

for file in test_files/positive/custom_project/*.json; do
    if [ -f "$file" ]; then
        export SBOM_FILE="$file"
        echo "Testing --project name SBOM FILE $SBOM_FILE"
        if [ "$1" = "--debug" ]; then
            poetry run python3 main.py --project-name="PROJECT-NAME-$file" --debug monitor
        else
            poetry run python3 main.py --project-name="PROJECT-NAME-$file" monitor
        fi
    fi
done

#pkg:npm/ant-design/icons
for dir in test_files/positive/root_node/*.json; do
    if [ -d "$dir" ]; then
        for file in $dir; do
            if [ -f "$file" ]; then
                export SBOM_FILE="$file"
                echo "Testing --root_node SBOM FILE $SBOM_FILE"
                if [ "$1" = "--debug" ]; then
                    poetry run python3 main.py --root-node="$dir" --debug monitor
                else
                    poetry run python3 main.py --root-node="$dir" monitor
                fi
            fi
        done
    fi
done

for file in test_files/negative/*.json; do
    if [ -f "$file" ]; then
        export SBOM_FILE="$file"
        echo "Testing negative SBOM FILE $SBOM_FILE"
        if [ "$1" = "--debug" ]; then
            poetry run python3 main.py --project-name="negative-test-$file" --debug monitor
        else
            poetry run python3 main.py --project-name="negative-test-$file" monitor
        fi
    fi
done

export SBOM_FILE=test_files/custom/sbom_webnext_test_1.json
poetry run python3 main.py --root-node=pkg:npm/@ant-design/icons@4.8.3 --debug monitor
poetry run python3 main.py --root-node=pkg:npm/ant-design/icons --debug monitor
poetry run python3 main.py --root-node=pkg:npm/@ant-design/icons@4.8.3 --project-name=CUSTOM-icons@4.8.3 --debug monitor

export SBOM_FILE=test_files/custom/page-servicebom.json
poetry run python3 main.py --project-name=CUSTOM-page-servicebom --debug monitor