package com.C9group34.socialnetworkproject.dto;

import com.C9group34.socialnetworkproject.models.Publication;
import com.C9group34.socialnetworkproject.models.User;

public class FavoritePublicationDto {

    private int id;

    private User user;

    private Publication publication;

    public FavoritePublicationDto() {

    }

    public FavoritePublicationDto(int id, User user, Publication publication) {
        this.id = id;
        this.user = user;
        this.publication = publication;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public User getUser() {
        return user;
    }

    public void setUser(User user) {
        this.user = user;
    }

    public Publication getPublication() {
        return publication;
    }

    public void setPublication(Publication publication) {
        this.publication = publication;
    }
}
