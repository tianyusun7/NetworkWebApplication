package service

import (
    "reflect"
    "mime/multipart"
    
    "around/backend"
    "around/constants"
    "around/model"

    "github.com/olivere/elastic/v7"
)

// select * from post where user = xxx
func SearchPostsByUser(user string) ([]model.Post, error) {
    query := elastic.NewTermQuery("user", user)
    searchResult, err := backend.ESBackend.ReadFromES(query, constants.POST_INDEX)
    if err != nil {
        return nil, err
    }
    return getPostFromSearchResult(searchResult), nil
}

// select * from post where message like "%keyword%" (much slower than match query) 
func SearchPostsByKeywords(keywords string) ([]model.Post, error) {
    query := elastic.NewMatchQuery("message", keywords)
    query.Operator("AND")
    if keywords == "" {
        query.ZeroTermsQuery("all")
    }
    searchResult, err := backend.ESBackend.ReadFromES(query, constants.POST_INDEX)
    if err != nil {
        return nil, err
    }
    return getPostFromSearchResult(searchResult), nil
}

func getPostFromSearchResult(searchResult *elastic.SearchResult) []model.Post {
    var ptype model.Post
    var posts []model.Post

    for _, item := range searchResult.Each(reflect.TypeOf(ptype)) { // ptype: to restrict type as POST, 
                                                                    // because of NoSql data
        p := item.(model.Post)
        posts = append(posts, p)
    }
    return posts
}

func SavePost(post *model.Post, file multipart.File) error {
    medialink, err := backend.GCSBackend.SaveToGCS(file, post.Id)
    if err != nil {
        return err
    }
    post.Url = medialink

    return backend.ESBackend.SaveToES(post, constants.POST_INDEX, post.Id)
}

