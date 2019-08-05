package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/filters"
	"github.com/docker/docker/api/types/mount"
	"github.com/docker/docker/client"
	log "github.com/sirupsen/logrus"
	logrus_syslog "github.com/sirupsen/logrus/hooks/syslog"
	"golang.org/x/sync/errgroup"
	"io"
	"io/ioutil"
	"log/syslog"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	timeToWait   = 3 * time.Minute
	composeFilesPath = "/tmp/deployer/compose"
)

type mapping struct {
	Node    string   `json:"node"`
	Type    string   `json:"type,omitempty"`
	Run     string   `json:"run,omitempty"`
	Monitor []string `json:"monitor,omitempty"`
	As      string   `json:"as,omitempty"`
	After   string   `json:"after,omitempty"`
}

type Deployer struct {
	dClient    *client.Client
	authBase64 string
	hostname   string
	homeDir    string
}

var deployer Deployer

func init() {
	hook, err := logrus_syslog.NewSyslogHook("udp", os.Getenv("DEPLOYER_SYSLOG_ADDRESS"), syslog.LOG_INFO, "")
	if err != nil {
		log.Error("Unable to connect to local syslog daemon")
	} else {
		log.AddHook(hook)
	}

	dClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		log.Fatalf("NewClientWithOpts: %+v\n", err)
	}
	dClient.NegotiateAPIVersion(context.Background())

	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("os.Hostname(): %+v\n", err)
	}

	auth := types.AuthConfig{
		ServerAddress: fmt.Sprintf("https://%s", os.Getenv("DEPLOYER_REGISTRY_ADDRESS")),
		Username:      os.Getenv("DEPLOYER_REGISTRY_USERNAME"),
		Password:      os.Getenv("DEPLOYER_REGISTRY_PASSWORD"),
	}
	authBytes, _ := json.Marshal(auth)
	authBase64 := base64.URLEncoding.EncodeToString(authBytes)

	usr, err := user.Current()
	if err != nil {
		log.Fatalf("user.Current(): %+v\n", err)
	}

	deployer = Deployer{
		dClient:    dClient,
		authBase64: authBase64,
		hostname:   hostname,
		homeDir:    usr.HomeDir,
	}
}

func main() {
	ctx := context.Background()
	mappings, err := deployer.updateHostConfig()
	if err != nil {
		log.Fatalf("updateHostConfig: %+v\n", err)
	}

	images, err := deployer.pullImages(ctx, mappings)
	if err != nil {
		log.Fatalf("pullImages: %+v\n", err)
	}

	containersToDeploy := deployer.generateContainersToDeploy(ctx, mappings, images)
	if len(containersToDeploy) == 0 {
		log.Exit(0)
	}

	log.Infof("mapsToDeploy: %+v\n", containersToDeploy)
	if err := toWait(deployer.hostname); err != nil {
		log.Fatalf("toWait: %+v\n", err)
	}

	if err := deployer.deploy(ctx, containersToDeploy); err != nil {
		log.Errorf("deploy: %+v\n", err)
	}
}

func (d *Deployer) deploy(ctx context.Context, containersToDeploy map[string]mapping) error {
	wg := errgroup.Group{}
	for _, v := range containersToDeploy {
		m := v
		wg.Go(func() error {
			if err := deployer.extractComposeFiles(ctx, m); err != nil {
				return err
			}

			runServiceCmd := fmt.Sprintf("cd %s/%s && ./docker-compose-action.sh %s %s", composeFilesPath, m.Type, m.Run, m.Type)
			_, err := runCommand(runServiceCmd)
			if err != nil {
				return err
			}
			log.Infof("SUCCESS:	%s	%s\n", m.Type, m.Run)
			//log.Debugf("DEPLOY: %s | cmd: %s \n %s\n", m.Type, runServiceCmd, runOutput)
			return nil
		})
	}

	return wg.Wait()
}

func (d *Deployer) generateContainersToDeploy(ctx context.Context, mappings []mapping, images map[string]types.ImageSummary) map[string]mapping {
	mapsToDeploy := make(map[string]mapping)
	for _, m := range mappings {
		for _, imgName := range m.Monitor {
			cs, err := deployer.getContainers(ctx,
				filters.KeyValuePair{
					Key:   "ancestor",
					Value: imgName,
				},
				filters.KeyValuePair{
					Key:   "name",
					Value: m.Type,
				})

			if err != nil {
				log.Errorf("getContainers: %+v\n", err)
				continue
			}

			if len(cs) == 0 {
				mapsToDeploy[m.Type] = m
				continue
			}

			isNew, err := isNewImage(cs[0].ImageID, imgName, images)
			if err != nil {
				log.Errorf("isNewImage: %+v\n", err)
				continue
			}

			if isNew {
				mapsToDeploy[m.Type] = m
				continue
			}
		}
	}

	return mapsToDeploy
}

func (d *Deployer) updateHostConfig() ([]mapping, error) {
	ms, err := d.getMappings()
	if err != nil {
		return nil, errors.New(fmt.Sprintf("getMappings(): %+v", err))
	}

	maps := getMapsByHostname(ms, d.hostname)
	if len(maps) == 0 {
		return nil, errors.New(fmt.Sprintf("getMapByHostname() not found: %s", d.hostname))
	}

	return maps, nil
}

func (d *Deployer) pullImages(ctx context.Context, maps []mapping) (map[string]types.ImageSummary, error) {
	pulledImages := make(map[string]bool)
	mutex := &sync.Mutex{}
	wg := errgroup.Group{}
	for _, m := range maps {
		for _, img := range m.Monitor {
			i := img
			wg.Go(func() error {
				mutex.Lock()
				if _, ok := pulledImages[i]; ok {
					mutex.Unlock()
					return nil
				}

				pulledImages[i] = true
				mutex.Unlock()
				return d.pullImage(ctx, i)
			})
		}
	}

	if err := wg.Wait(); err != nil {
		return nil, err
	}

	if _, err := d.dClient.ImagesPrune(ctx, filters.Args{}); err != nil {
		return nil, errors.New(fmt.Sprintf("ImagesPrune: %+v", err))
	}

	images, err := d.getImagesByName(ctx)
	if err != nil {
		return images, nil
	}
	return images, nil
}

func (d *Deployer) extractComposeFiles(ctx context.Context, m mapping) error {
	composePath := fmt.Sprintf("%s/%s", composeFilesPath, m.Type)
	if err := os.MkdirAll(composePath, os.ModePerm); err != nil {
		return errors.New(fmt.Sprintf("MkdirAll: %+v", err))
	}

	c, err := d.dClient.ContainerCreate(ctx,
		&container.Config{
			Image: m.Run,
			Cmd:   []string{"/bin/sh", "-c", "cp /app/docker-compose* /compose"},
		},
		&container.HostConfig{
			Mounts: []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: composePath,
					Target: "/compose",
				},
			},
			AutoRemove: true,
		},
		nil,
		"",
	)

	if err != nil {
		return errors.New(fmt.Sprintf(" cli.ContainerCreate: %+v", err))
	}


	if err := d.dClient.ContainerStart(ctx, c.ID, types.ContainerStartOptions{}); err != nil {
		return errors.New(fmt.Sprintf("ContainerStart: %+v", err))
	}

	return nil
}

func (d *Deployer) pullImage(ctx context.Context, image string) error {
	reader, err := d.dClient.ImagePull(ctx, image, types.ImagePullOptions{
		RegistryAuth: d.authBase64,
	})

	if err != nil {
		return errors.New(fmt.Sprintf("pullImage %+v", err))
	}

	if _, err := io.Copy(ioutil.Discard, reader); err != nil {
		return errors.New(fmt.Sprintf("io.Copy: %+v", err))
	}

	return nil
}

func (d *Deployer) getImagesByName(ctx context.Context) (map[string]types.ImageSummary, error) {
	imagesSummary, err := d.dClient.ImageList(ctx, types.ImageListOptions{})
	if err != nil {
		return nil, errors.New(fmt.Sprintf("cli.ImageList: %+v", err))
	}

	images := make(map[string]types.ImageSummary)
	for _, image := range imagesSummary {
		if len(image.RepoTags) == 0 {
			continue
		}

		for _, tag := range image.RepoTags {
			images[tag] = image
		}
	}

	//for k, v := range images {
	//	log.Debugf("image: %s | %+v\n", k, v.ID)
	//}

	return images, nil
}

func (d *Deployer) getContainers(ctx context.Context, filter ...filters.KeyValuePair) ([]types.Container, error) {
	cs, err := d.dClient.ContainerList(ctx, types.ContainerListOptions{
		Filters: filters.NewArgs(filter...),
	})

	if len(cs) > 1 {
		return nil, errors.New(fmt.Sprintf("cli.ContainerList2: Too much containers"))
	}

	if err != nil {
		return nil, errors.New(fmt.Sprintf("cli.ContainerList: %+v", err))
	}

	return cs, nil
}

func (d *Deployer) getMappings() ([]mapping, error) {
	var (
		m []mapping
		config *os.File
		err error
	)

	parse := func() ([]mapping, error) {
		byteValue, _ := ioutil.ReadAll(config)
		return m, json.Unmarshal(byteValue, &m)
	}

	config, err = os.Open("config/mapping.json")
	if err == nil {
		defer config.Close()
		return parse()
	}

	config, err = os.Open(fmt.Sprintf("%s/.deployer/mapping.json", d.homeDir))
	if err != nil {
		return nil, errors.New(fmt.Sprintf("os.Open: %+v", err))
	}

	defer config.Close()
	return parse()
}

func isNewImage(cImageId, imgName string, images map[string]types.ImageSummary) (bool, error) {
	if !strings.Contains(imgName, ":") {
		imgName = imgName + ":latest"
	}

	img, ok := images[imgName]
	if !ok {
		return false, errors.New(fmt.Sprintf("isNewImage: cannot found image: %s", imgName))
	}

	if img.ID != cImageId {
		return true, nil
	}

	return false, nil
}

func toWait(hostname string) error {
	if strings.HasPrefix(hostname, "worker") {
		workerNum, err := strconv.Atoi(hostname[len(hostname)-1:])
		if err != nil {
			return errors.New(fmt.Sprintf("strconv.Atoi: %+v", err))
		}

		if workerNum > 2 {
			log.Printf("timeToWait: %s\n", timeToWait)
			time.Sleep(timeToWait)
		}
	}
	return nil
}

func runCommand(cmd string) (string, error) {
	command := exec.Command("sh", "-c", cmd)
	out, err := command.CombinedOutput()
	if err != nil {
		return "", errors.New(fmt.Sprintf("runCommand: %+v | %s", err, string(out)))
	}
	return string(out), nil
}

func getMapsByHostname(ms []mapping, hostname string) []mapping {
	getMappings := func(hs string) []mapping {
		var maps []mapping
		for _, v := range ms {
			if v.Node == hs {
				maps = append(maps, v)
			}
		}
		return maps
	}

	maps := getMappings(hostname)
	if len(maps) == 1 && len(maps[0].As) > 0 {
		maps = getMappings(maps[0].As)
	}
	return maps
}
