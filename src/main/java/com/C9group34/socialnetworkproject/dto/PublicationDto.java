package com.C9group34.socialnetworkproject.dto;

import java.util.List;

public class PublicationDto {

    private int id;

    private String title;

    private String description;

    private String urlImg;

    private Double rating;

    private String status;

    private List<CommentDto> comments;

    public PublicationDto(){

    }

    public PublicationDto(int id, String title, String description,
                          String urlImg, Double rating, String status, List<CommentDto> comments) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.urlImg = urlImg;
        this.rating = rating;
        this.status = status;
        this.comments = comments;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public String getUrlImg() {
        return urlImg;
    }

    public void setUrlImg(String urlImg) {
        this.urlImg = urlImg;
    }

    public Double getRating() {
        return rating;
    }

    public void setRating(Double rating) {
        this.rating = rating;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public List<CommentDto> getComments() {
        return comments;
    }

    public void setComments(List<CommentDto> comments) {
        this.comments = comments;
    }
}
