package com.C9group34.socialnetworkproject.dto;

import com.C9group34.socialnetworkproject.repository.PublicationRepository;

import java.util.List;

public class CategoryDto {

    private Integer id;
    private String title;
    private String description;
    private List<PublicationRepository> publications;



    public CategoryDto(){

    }

    public CategoryDto(int id, String title, String description, List<PublicationRepository> publications) {
        this.id = id;
        this.title = title;
        this.description = description;
        this.publications = publications;
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

    public List<PublicationRepository> getPublications() {
        return publications;
    }

    public void setPublications(List<PublicationRepository> publications) {
        this.publications = publications;
    }
}
