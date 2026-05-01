FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Prevent Python from buffering logs (makes logs appear instantly)
ENV PYTHONUNBUFFERED=1

# Install the missing Python libraries directly
RUN pip install --no-cache-dir requests numpy

# Copy all scripts into the container
COPY . .

# Run the brain of the operation
CMD ["python", "main.py"]
