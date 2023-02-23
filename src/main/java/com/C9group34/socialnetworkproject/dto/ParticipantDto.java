package com.C9group34.socialnetworkproject.dto;

import com.C9group34.socialnetworkproject.models.User;

import java.util.List;

public class ParticipantDto {

    private int id;

    private List<User> pars;

    public ParticipantDto(int id) {
        this.id = id;
    }

    public ParticipantDto(int id, List<User> pars) {
        this.id = id;
        this.pars = pars;
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public List<User> getPars() {
        return pars;
    }

    public void setPars(List<User> pars) {
        this.pars = pars;
    }
}
