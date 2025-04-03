package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	mapset "github.com/deckarep/golang-set/v2"
	"github.com/labstack/echo/v4"
	"github.com/samber/mo"
	"gorm.io/gorm"
	"log"
	"net/http"
	"strings"
	"time"
)

type PlayerNameToIDResponse struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type playerNameToIDJob struct {
	LowerName string
	ReturnCh  chan mo.Option[PlayerNameToIDResponse]
}

func (fallbackAPIServer *FallbackAPIServer) PlayerNamesToIDs(remainingLowerNames mapset.Set[string]) []PlayerNameToIDResponse {
	responses := make([]PlayerNameToIDResponse, 0, remainingLowerNames.Cardinality())

	// Use responses from the cache, if available.
	if fallbackAPIServer.PlayerNameToIDCache != nil {
		for _, lowerName := range remainingLowerNames.ToSlice() {
			cachedResponse, found := fallbackAPIServer.PlayerNameToIDCache.Get(lowerName)
			if found {
				remainingLowerNames.Remove(lowerName)
				if response, isPresent := cachedResponse.(mo.Option[PlayerNameToIDResponse]).Get(); isPresent {
					responses = append(responses, response)
				}
			}
		}
	}

	playerNameToIDJobs := make([]playerNameToIDJob, 0, remainingLowerNames.Cardinality())
	for lowerName := range mapset.Elements(remainingLowerNames) {
		playerNameToIDJobs = append(playerNameToIDJobs, playerNameToIDJob{
			LowerName: lowerName,
			ReturnCh:  make(chan mo.Option[PlayerNameToIDResponse], 1),
		})
	}
	fallbackAPIServer.PlayerNameToIDJobCh <- playerNameToIDJobs

	for _, job := range playerNameToIDJobs {
		maybeRes := <-job.ReturnCh
		if res, ok := maybeRes.Get(); ok {
			responses = append(responses, res)
		}
	}
	return responses
}

func (app *App) PlayerNamesToIDsWorker(fallbackAPIServer *FallbackAPIServer) {
	// All communication with the POST /profiles/minecraft (a.k.a. POST
	// /minecraft/profile/lookup/bulk/byname) route on a fallback API server is
	// done by a single goroutine running this function. It buffers a queue of
	// requested (lowercase) player names and makes requests to the fallback
	// API server in batches of MAX_PLAYER_NAMES_TO_IDS, waiting at least
	// MAX_PLAYER_NAMES_TO_IDS_INTERVAL in between requests, in order to avoid
	// rate-limiting.

	url := fallbackAPIServer.Config.AccountURL + "/profiles/minecraft"

	// Queue of player names to fetch that may exceed MAX_PLAYER_NAMES_TO_IDS
	// in size
	lowerNameQueue := make([]*string, 0)

	// Map lowercase player name to a list of return channels where we should
	// send the result of the query for that lowercase player name
	lowerNameToResponseChs := make(map[string][]chan mo.Option[PlayerNameToIDResponse])

	var timeout <-chan time.Time = nil

	for {
		select {
		case jobs := <-fallbackAPIServer.PlayerNameToIDJobCh:
			for _, job := range PtrSlice(jobs) {
				// Double-check the cache
				if fallbackAPIServer.PlayerNameToIDCache != nil {
					cachedResponse, found := fallbackAPIServer.PlayerNameToIDCache.Get(job.LowerName)
					if found {
						job.ReturnCh <- cachedResponse.(mo.Option[PlayerNameToIDResponse])
						continue
					}
				}

				// Double-check for validity, invalid player names will spoil
				// the entire batch. We will assume that if a player name is
				// valid to Drasl, it is valid on all fallback API servers (if
				// this becomes a problem in the future, we may need a
				// FallbackAPIServer.ValidPlayerNameRegex.
				if app.ValidatePlayerName(job.LowerName) != nil {
					job.ReturnCh <- mo.None[PlayerNameToIDResponse]()
					continue
				}

				if _, ok := lowerNameToResponseChs[job.LowerName]; !ok {
					lowerNameQueue = append(lowerNameQueue, &job.LowerName)
				}
				lowerNameToResponseChs[job.LowerName] = append(lowerNameToResponseChs[job.LowerName], job.ReturnCh)
			}
		case <-timeout:
			timeout = nil
		}

		// Wait until we have player names in the queue AND have waited long
		// enough to make another request
		if !(len(lowerNameQueue) > 0 && timeout == nil) {
			continue
		}

		// Dequeue the next batch of MAX_PLAYER_NAMES_TO_IDS lowercase player names
		batchSize := min(len(lowerNameQueue), MAX_PLAYER_NAMES_TO_IDS)
		batch := lowerNameQueue[:batchSize]
		lowerNameQueue = lowerNameQueue[batchSize:]

		fallbackResponses, fallbackError := (func() ([]PlayerNameToIDResponse, error) {
			body, err := json.Marshal(batch)
			if err != nil {
				return nil, err
			}

			res, err := MakeHTTPClient().Post(url, "application/json", bytes.NewBuffer(body))
			if err != nil {
				return nil, err
			}
			defer res.Body.Close()

			if res.StatusCode != http.StatusOK {
				return nil, fmt.Errorf("received status code %d", res.StatusCode)
			}

			buf := new(bytes.Buffer)
			_, err = buf.ReadFrom(res.Body)
			if err != nil {
				return nil, err
			}

			var fallbackResponses []PlayerNameToIDResponse
			err = json.Unmarshal(buf.Bytes(), &fallbackResponses)
			if err != nil {
				return nil, err
			}
			return fallbackResponses, nil
		})()

		timeout = time.After(MAX_PLAYER_NAMES_TO_IDS_INTERVAL)

		lowerNameToResponse := make(map[string]*PlayerNameToIDResponse)
		if fallbackError != nil {
			log.Printf("Error requesting player IDs from fallback API server at %s: %s", url, fallbackError)
		} else {
			for _, fallbackResponse := range PtrSlice(fallbackResponses) {
				lowerName := strings.ToLower(fallbackResponse.Name)
				lowerNameToResponse[lowerName] = fallbackResponse
			}
		}

		for _, lowerName := range batch {
			if fallbackError == nil && fallbackAPIServer.PlayerNameToIDCache != nil {
				ttl := time.Duration(fallbackAPIServer.Config.CacheTTLSeconds) * time.Second
				if res, ok := lowerNameToResponse[*lowerName]; ok {
					fallbackAPIServer.PlayerNameToIDCache.SetWithTTL(*lowerName, mo.Some(*res), 0, ttl)
				} else {
					fallbackAPIServer.PlayerNameToIDCache.SetWithTTL(*lowerName, mo.None[PlayerNameToIDResponse](), 0, ttl)
				}
				fallbackAPIServer.PlayerNameToIDCache.Wait()
			}
			for _, responseCh := range lowerNameToResponseChs[*lowerName] {
				if res, ok := lowerNameToResponse[*lowerName]; ok {
					responseCh <- mo.Some(*res)
				} else {
					responseCh <- mo.None[PlayerNameToIDResponse]()
				}
			}
		}
		clear(lowerNameToResponseChs)
	}
}

// GET /users/profiles/minecraft/:playerName
// GET /minecraft/profile/lookup/name/:playerName
// https://minecraft.wiki/w/Mojang_API#Query_player's_UUID
func AccountPlayerNameToID(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		playerName := c.Param("playerName")

		if len(playerName) > Constants.MaxPlayerNameLength {
			// This error message is consistent with GET
			// https://api.mojang.com/users/profiles/minecraft/:playerName as
			// of 2025-04-02
			errorMessage := fmt.Sprintf("getProfileName.name: Invalid profile name, getProfileName.name: size must be between 1 and %d", Constants.MaxPlayerNameLength)
			return &YggdrasilError{
				Code:         http.StatusBadRequest,
				Error_:       mo.Some("CONSTRAINT_VIOLATION"),
				ErrorMessage: mo.Some(errorMessage),
			}
		}

		lowerName := strings.ToLower(playerName)
		if app.ValidatePlayerName(lowerName) != nil {
			// This error message is consistent with POST
			// https://api.mojang.com/users/profiles/minecraft/:playerName as
			// of 2025-04-03
			errorMessage := fmt.Sprintf("getProfileName.name: Invalid profile name")
			return &YggdrasilError{
				Code:         http.StatusBadRequest,
				Error_:       mo.Some("CONSTRAINT_VIOLATION"),
				ErrorMessage: mo.Some(errorMessage),
			}
		}

		var player Player
		result := app.DB.First(&player, "name = ?", lowerName)
		if result.Error != nil {
			if errors.Is(result.Error, gorm.ErrRecordNotFound) {
				for _, fallbackAPIServer := range app.FallbackAPIServers {
					fallbackResponses := fallbackAPIServer.PlayerNamesToIDs(mapset.NewSet(lowerName))
					if len(fallbackResponses) == 1 && strings.EqualFold(lowerName, fallbackResponses[0].Name) {
						return c.JSON(http.StatusOK, fallbackResponses[0])
					}
				}
				errorMessage := fmt.Sprintf("Couldn't find any profile with name %s", playerName)
				return &YggdrasilError{Code: http.StatusNotFound, ErrorMessage: mo.Some(errorMessage)}
			}
			return result.Error
		}

		id, err := UUIDToID(player.UUID)
		if err != nil {
			return err
		}
		res := PlayerNameToIDResponse{
			Name: player.Name,
			ID:   id,
		}

		return c.JSON(http.StatusOK, res)
	}
}

// POST /profiles/minecraft
// POST /minecraft/profile/lookup/bulk/byname
// https://minecraft.wiki/w/Mojang_API#Query_player_UUIDs_in_batch
func AccountPlayerNamesToIDs(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		var playerNames []string
		if err := json.NewDecoder(c.Request().Body).Decode(&playerNames); err != nil {
			return err
		}

		if len(playerNames) == 0 {
			// This error message is consistent with POST
			// https://api.mojang.com/profiles/minecraft as of 2025-04-02
			errorMessage := fmt.Sprintf("getProfileName.profileNames: must not be empty")
			return &YggdrasilError{
				Code:         http.StatusBadRequest,
				Error_:       mo.Some("CONSTRAINT_VIOLATION"),
				ErrorMessage: mo.Some(errorMessage),
			}
		}
		if len(playerNames) > MAX_PLAYER_NAMES_TO_IDS {
			// This error message is consistent with POST
			// https://api.mojang.com/profiles/minecraft as of 2025-04-02
			errorMessage := fmt.Sprintf("getProfileName.profileNames: size must be between 0 and %d", MAX_PLAYER_NAMES_TO_IDS)
			return &YggdrasilError{
				Code:         http.StatusBadRequest,
				Error_:       mo.Some("CONSTRAINT_VIOLATION"),
				ErrorMessage: mo.Some(errorMessage),
			}
		}

		response := make([]PlayerNameToIDResponse, 0, len(playerNames))

		remainingLowerNames := mapset.NewSet[string]()
		for i, playerName := range playerNames {
			if !(1 <= len(playerName) && len(playerName) <= Constants.MaxPlayerNameLength) {
				// This error message is consistent with POST
				// https://api.mojang.com/profiles/minecraft as of 2025-04-02
				errorMessage := fmt.Sprintf("getProfileName.profileNames[%d].<list element>: size must be between 1 and %d, getProfileName.profileNames[%d].<list element>: Invalid profile name", i, Constants.MaxPlayerNameLength, 1)
				return &YggdrasilError{
					Code:         http.StatusBadRequest,
					Error_:       mo.Some("CONSTRAINT_VIOLATION"),
					ErrorMessage: mo.Some(errorMessage),
				}
			}

			lowerName := strings.ToLower(playerName)
			if app.ValidatePlayerName(lowerName) != nil {
				// This error message is consistent with POST
				// https://api.mojang.com/profiles/minecraft as of 2025-04-03
				errorMessage := fmt.Sprintf("getProfileName.profileNames[%d].<list element>: Invalid profile name", i)
				return &YggdrasilError{
					Code:         http.StatusBadRequest,
					Error_:       mo.Some("CONSTRAINT_VIOLATION"),
					ErrorMessage: mo.Some(errorMessage),
				}
			}

			remainingLowerNames.Add(lowerName)
		}

		for _, lowerName := range remainingLowerNames.ToSlice() {
			var player Player
			result := app.DB.First(&player, "name = ?", lowerName)
			if result.Error != nil {
				if !errors.Is(result.Error, gorm.ErrRecordNotFound) {
					return result.Error
				}
			} else {
				id, err := UUIDToID(player.UUID)
				if err != nil {
					return err
				}
				playerRes := PlayerNameToIDResponse{
					Name: player.Name,
					ID:   id,
				}
				response = append(response, playerRes)
				remainingLowerNames.Remove(lowerName)
			}
		}

		for _, fallbackAPIServer := range app.FallbackAPIServers {
			if remainingLowerNames.Cardinality() == 0 {
				break
			}

			fallbackResponses := fallbackAPIServer.PlayerNamesToIDs(remainingLowerNames)
			for _, fallbackResponse := range fallbackResponses {
				lowerName := strings.ToLower(fallbackResponse.Name)
				if remainingLowerNames.Contains(lowerName) {
					response = append(response, fallbackResponse)
					remainingLowerNames.Remove(lowerName)
				}
			}
		}

		return c.JSON(http.StatusOK, response)
	}
}

// GET /user/security/location
func AccountVerifySecurityLocation(app *App) func(c echo.Context) error {
	return func(c echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	}
}
