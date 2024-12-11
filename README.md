# Simple Rust Falco plugin
This repo contains a simple Rust Falco plugin that generates random numbers as events.

## Usage
1. Clone this repository
2. Install Rust and Cargo
3. Run `cargo build --release`

This should generate a shared object file in the `target/release` directory.

## Running the plugin
You need a running Falco instance to test the plugin. You can use the [Falco Docker image](https://hub.docker.com/r/falcosecurity/falco) to get started.
You can use this command to start the container:

```bash
sudo docker run --rm -i -t --name falco --privileged  \
    -v /var/run/docker.sock:/host/var/run/docker.sock \
    -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro \
    -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro \
    v /path/to/falco.yaml:/etc/falco/falco.yaml \
    falcosecurity/falco:latest
```

You can load the plugin by adding it in the Falco configuration file (falco.yaml):

```yaml
load_plugins: [random_generator]
plugins:
  - name: random_generator
    library_path: [FULL_PATH_TO_SO_FILE]/librand_generator_plugin.so
    init_config:
      range: 1000 # The range of the random numbers
```

Then restart Falco to load the plugin.
To test the plugin, you need to add a rule to the Falco configuration file that uses the plugin:

```yaml
- rule: random number generated
  desc: >
    random number generated
  condition: gen.num > 0
  output: "A random number was generated %gen.num"
  priority: INFO
  source: random_generator
  tags: [random_generator, rust]
```