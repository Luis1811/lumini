package com.C9group34.socialnetworkproject.dto;

public class ConversationDto {
    private int id;
    private String title;
    private int creator_id;

    public ConversationDto(String title, int creator) {
    }

    public ConversationDto(int id, String title, int creator_id) {
        this.id = id;
        this.title = title;
        this.creator_id = creator_id;
    }

    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public int getCreator() { return creator_id; }
    public void setCreator(int creator_id) { this.creator_id = creator_id; }
}

