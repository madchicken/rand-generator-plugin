# Simple Rust Falco plugin
This repo contains a simple Rust Falco plugin that generates random numbers as events.

## Usage
1. Clone this repository
2. Install Rust and Cargo
3. Run `cargo build --release`

This should generate a shared object file in the `target/release` directory.

## Running the plugin
You need a running Falco instance to test the plugin. You can use the [Falco Docker image](https://hub.docker.com/r/falcosecurity/falco) to get started.

Assuming that you are in the plugin directory and the plugin has been generated in `target/release/librand_generator_plugin.so` you can test it with Falco by running:

```bash
sudo docker run --rm -i -t --name falco --privileged  \
    -v /var/run/docker.sock:/host/var/run/docker.sock \
    -v /dev:/host/dev -v /proc:/host/proc:ro -v /boot:/host/boot:ro \
    -v /lib/modules:/host/lib/modules:ro -v /usr:/host/usr:ro -v /etc:/host/etc:ro \
  -v $(pwd)/target/release/librand_generator_plugin.so:/usr/share/falco/plugins/librand_generator_plugin.so \
  -v $(pwd)/example_rule.yaml:/etc/falco/example_rule.yaml \
    falcosecurity/falco:latest falco \
  -o 'plugins[]={"name":"random_generator","library_path":"/usr/share/falco/plugins/librand_generator_plugin.so","init_config":{"range":1000}}' \
  -o load_plugins[]=random_generator \
  -o rules_files[]=/etc/falco/example_rule.yaml
```

Note that the configuration above can be replicated in your local `falco.yaml`, if you already have Falco installed like so:

```yaml
load_plugins: [random_generator]
plugins:
  - name: random_generator
    library_path: [FULL_PATH_TO_SO_FILE]/librand_generator_plugin.so
    init_config:
      range: 1000 # The range of the random numbers
```
