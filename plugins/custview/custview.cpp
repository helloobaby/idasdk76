/* Custom viewer sample plugin.
 * Copyright (c) 2007 by Ilfak Guilfanov, ig@hexblog.com
 * Feel free to do whatever you want with this code.
 *
 * This sample plugin demonstates how to create and manipulate a simple
 * custom viewer in IDA v5.1
 *
 * Custom viewers allow you to create a view which displays colored lines.
 * These colored lines are dynamically created by callback functions.
 *
 * Custom viewers are used in IDA itself to display
 * the disassembly listng, structure, and enumeration windows.
 *
 * This sample plugin just displays several sample lines on the screen.
 * It displays a hint with the current line number.
 * The right-click menu contains one sample command.
 * It reacts to one hotkey.
 *
 * This plugin uses the simpleline_place_t class for the locations.
 * Custom viewers can use any decendant of the place_t class.
 * The place_t is responsible for supplying data to the viewer.
 */

//---------------------------------------------------------------------------
#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <kernwin.hpp>

#define ACTION_NAME "custview:SampleMenuItem"

struct plugin_ctx_t;
struct sample_action_t : public action_handler_t
{
  plugin_ctx_t &plg;
  sample_action_t(plugin_ctx_t &p) : plg(p) {}
  virtual int idaapi activate(action_activation_ctx_t *) override;
  virtual action_state_t idaapi update(action_update_ctx_t *) override
  {
    return AST_ENABLE_ALWAYS;
  }
};

//-------------------------------------------------------------------------
static struct
{
  const char *text;
  bgcolor_t color;
} const sample_text[] =
{
  { "This is a sample text",                                         0xFFFFFF },
  { "It will be displayed in the custom view",                       0xFFC0C0 },
  { COLSTR("This line will be colored as erroneous", SCOLOR_ERROR),  0xC0FFC0 },
  { COLSTR("Every", SCOLOR_AUTOCMT) " "
    COLSTR("word", SCOLOR_DNAME) " "
    COLSTR("can", SCOLOR_IMPNAME) " "
    COLSTR("be", SCOLOR_NUMBER) " "
    COLSTR("colored!", SCOLOR_EXTRA),                                0xC0C0FF },
  { "  No limit on the number of lines.",                            0xC0FFFF },
};

// Structure to keep all information about the our sample view
struct sample_info_t
{
  TWidget *cv;
  strvec_t sv;
  sample_info_t() : cv(NULL) {}
};

struct plugin_ctx_t : public plugmod_t, public event_listener_t
{
  sample_info_t *si = NULL;
  const sample_info_t *last_si = NULL;

  sample_action_t sample_ah = sample_action_t(*this);
  const action_desc_t sample_action = ACTION_DESC_LITERAL_PLUGMOD(
        ACTION_NAME,
        "Sample menu item",
        &sample_ah,
        this,
        "N",
        NULL,
        -1);

  virtual bool idaapi run(size_t) override;
  virtual ssize_t idaapi on_event(ssize_t code, va_list va) override;
};

//---------------------------------------------------------------------------
// get the word under the (keyboard or mouse) cursor
static bool get_current_word(TWidget *v, bool mouse, qstring &word)
{
  // query the cursor position
  int x, y;
  if ( get_custom_viewer_place(v, mouse, &x, &y) == NULL )
    return false;

  // query the line at the cursor
  qstring buf;
  tag_remove(&buf, get_custom_viewer_curline(v, mouse));
  if ( x >= buf.length() )
    return false;

  // find the beginning of the word
  char *ptr = buf.begin() + x;
  while ( ptr > buf.begin() && !qisspace(ptr[-1]) )
    ptr--;

  // find the end of the word
  char *begin = ptr;
  ptr = buf.begin() + x;
  while ( !qisspace(*ptr) && *ptr != '\0' )
    ptr++;

  word = qstring(begin, ptr-begin);
  return true;
}

//---------------------------------------------------------------------------
int idaapi sample_action_t::activate(action_activation_ctx_t *)
{
  qstring word;
  if ( !get_current_word(plg.last_si->cv, false, word) )
    return 0;

  info("The current word is: %s", word.c_str());
  return 1;
}

//---------------------------------------------------------------------------
// Keyboard callback
static bool idaapi ct_keyboard(TWidget * /*v*/, int key, int shift, void *ud)
{
  if ( shift == 0 )
  {
    sample_info_t *si = (sample_info_t *)ud;
    switch ( key )
    {
      case 'N':
        warning("The hotkey 'N' has been pressed");
        return true;
      case IK_ESCAPE:
        close_widget(si->cv, WCLS_SAVE | WCLS_CLOSE_LATER);
        return true;
    }
  }
  return false;
}

//---------------------------------------------------------------------------
// This callback will be called each time the keyboard cursor position
// is changed
static void idaapi ct_curpos(TWidget *v, void *)
{
  qstring word;
  if ( get_current_word(v, false, word) )
    msg("Current word is: %s\n", word.c_str());
}

//--------------------------------------------------------------------------
ssize_t idaapi plugin_ctx_t::on_event(ssize_t code, va_list va)
{
  switch ( code )
  {
    // how to implement a simple hint callback
    case ui_get_custom_viewer_hint:
      {
        qstring &hint = *va_arg(va, qstring *);
        TWidget *viewer = va_arg(va, TWidget *);
        place_t *place = va_arg(va, place_t *);
        int *important_lines = va_arg(va, int *);
        if ( si->cv == viewer ) // our viewer
        {
          if ( place == NULL )
            return 0;
          simpleline_place_t *spl = (simpleline_place_t *)place;
          hint.cat_sprnt("Hint for line %u\n", spl->n);
          *important_lines += 1;
        }
        break;
      }
    case ui_widget_invisible:
      {
        TWidget *f = va_arg(va, TWidget *);
        if ( f == si->cv )
        {
          delete si;
          si = nullptr;
          unhook_event_listener(HT_UI, this);
        }
      }
      break;
    case ui_populating_widget_popup:
      {
        TWidget *f = va_arg(va, TWidget *);
        if ( f == si->cv )
        {
          TPopupMenu *p = va_arg(va, TPopupMenu *);
          // Create right-click menu on the fly
          attach_action_to_popup(f, p, ACTION_NAME);
        }
      }
      break;
  }
  return 0;
}

//-------------------------------------------------------------------------
static const custom_viewer_handlers_t handlers(
        ct_keyboard,
        NULL, // popup
        NULL, // mouse_moved
        NULL, // click
        NULL, // dblclick
        ct_curpos,
        NULL, // close
        NULL, // help
        NULL);// adjust_place

//---------------------------------------------------------------------------
// Create a custom view window
bool idaapi plugin_ctx_t::run(size_t)
{
  TWidget *widget = find_widget("Sample custom view");
  if ( widget != NULL )
  {
    activate_widget(widget, true);
    return true;
  }

  // allocate block to hold info about our sample view
  si = new sample_info_t();
  last_si = si;
  // prepare the data to display. we could prepare it on the fly too.
  // but for that we have to use our own custom place_t class decendant.
  for ( int i=0; i < qnumber(sample_text); i++ )
  {
    si->sv.push_back(simpleline_t("")); // add empty line
    si->sv.push_back(simpleline_t(sample_text[i].text));
    si->sv.back().bgcolor = sample_text[i].color;
  }
  // create two place_t objects: for the minimal and maximal locations
  simpleline_place_t s1;
  simpleline_place_t s2(si->sv.size()-1);
  // create a custom viewer
  si->cv = create_custom_viewer("Sample custom view", &s1, &s2, &s1, NULL, &si->sv, &handlers, si);
  // also set the ui event callback
  hook_event_listener(HT_UI, this);
  // finally display the form on the screen
  display_widget(si->cv, WOPN_DP_TAB|WOPN_RESTORE);

  // Register the action. This one will be attached
  // live, to the popup menu.
  register_action(sample_action);
  return true;
}

//--------------------------------------------------------------------------
static plugmod_t *idaapi init()
{
  return new plugin_ctx_t;
}

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_MULTI,         // plugin flags
  init,                 // initialize

  nullptr,
  nullptr,

  "",                   // long comment about the plugin
  "",                   // multiline help about the plugin
  "Sample custview",    // the preferred short name of the plugin
  ""                    // the preferred hotkey to run the plugin
};
